#include "tessera/hook/hook.hpp"

#include <Windows.h>

#include <limits>
#include <new>
#include <utility>

#include "platform/windows/thread_backend.hpp"
#include "tessera/core/assert.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/process/process.hpp"

#if defined(TESSERA_WITH_DETOURS_ENABLED)
    #if __has_include(<detours/detours.h>)
        #include <detours/detours.h>
    #elif __has_include(<detours.h>)
        #include <detours.h>
    #else
        #error "TESSERA_WITH_DETOURS is ON, but detours.h could not be found."
    #endif
#endif

namespace tessera {

namespace {

[[nodiscard]] constexpr bool is_valid_thread_policy(ThreadPolicy policy) noexcept {
    return policy == ThreadPolicy::SuspendOthersStrict ||
           policy == ThreadPolicy::SuspendOthersBestEffort ||
           policy == ThreadPolicy::None;
}

class DefaultHookBackend final : public HookBackend {
public:
    [[nodiscard]] bool available() const noexcept override {
#if defined(TESSERA_WITH_DETOURS_ENABLED)
        return true;
#else
        return native_inline_hook_backend().available();
#endif
    }

    [[nodiscard]] Result<HookToken> attach([[maybe_unused]] Address target,
                                           [[maybe_unused]] void* detour,
                                           const HookOptions& options) override {
        if (!is_valid_thread_policy(options.threads)) {
            return fail(ErrorCode::InvalidArgument,
                        "DefaultHookBackend::attach",
                        0,
                        "Unknown thread coordination policy");
        }
#if defined(TESSERA_WITH_DETOURS_ENABLED)
        const int max_attempts = (options.threads == ThreadPolicy::None) ? 1 : 3;
        LONG last_err = NO_ERROR;

        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            platform::windows::ProcessWideHookLock lock{};
            if (!lock.acquired()) {
                return fail(ErrorCode::IoError, "ProcessWideHookLock", ::GetLastError());
            }

            auto threads_res = platform::windows::ScopedThreadList::collect_other_threads(options.threads, true);
            if (!threads_res) {
                return std::unexpected(threads_res.error());
            }

            LONG err = ::DetourTransactionBegin();
            if (err != NO_ERROR) {
                last_err = err;
                if (err == ERROR_INVALID_OPERATION) {
                    continue;
                }
                return fail(ErrorCode::Conflict, "DetourTransactionBegin", static_cast<std::uint32_t>(err));
            }

            err = ::DetourUpdateThread(::GetCurrentThread());
            bool ok_step = (err == NO_ERROR);
            const char* failed_operation = "DetourUpdateThread";
            for (void* th : threads_res->handles()) {
                if (!ok_step) {
                    break;
                }
                err = ::DetourUpdateThread(static_cast<HANDLE>(th));
                if (err != NO_ERROR && options.threads == ThreadPolicy::SuspendOthersStrict) {
                    ok_step = false;
                    failed_operation = "DetourUpdateThread";
                }
            }

            void* tramp = reinterpret_cast<void*>(static_cast<std::uintptr_t>(target.value()));
            if (ok_step) {
                failed_operation = "DetourAttach";
                err = ::DetourAttach(&tramp, detour);
                ok_step = (err == NO_ERROR);
            }

            if (!ok_step) {
                ::DetourTransactionAbort();
                return fail(ErrorCode::InvalidArgument, failed_operation, static_cast<std::uint32_t>(err));
            }

            err = ::DetourTransactionCommit();
            if (err == NO_ERROR) {
                return HookToken{
                    .target = reinterpret_cast<void*>(static_cast<std::uintptr_t>(target.value())),
                    .detour = detour,
                    .trampoline = tramp,
                    .threads = options.threads,
                    .observer = options.observer,
                };
            }
            last_err = err;
        }
        return fail(ErrorCode::Conflict, "DetourTransactionCommit", static_cast<std::uint32_t>(last_err));
#else
        return native_inline_hook_backend().attach(target, detour, options);
#endif
    }

    [[nodiscard]] Status detach(HookToken& token) override {
        if (!is_valid_thread_policy(token.threads)) {
            return fail(ErrorCode::InvalidArgument,
                        "DefaultHookBackend::detach",
                        0,
                        "Unknown thread coordination policy in hook token");
        }
#if defined(TESSERA_WITH_DETOURS_ENABLED)
        const int max_attempts = (token.threads == ThreadPolicy::None) ? 1 : 3;
        LONG last_err = NO_ERROR;

        for (int attempt = 0; attempt < max_attempts; ++attempt) {
            platform::windows::ProcessWideHookLock lock{};
            if (!lock.acquired()) {
                return fail(ErrorCode::IoError, "ProcessWideHookLock", ::GetLastError());
            }

            auto threads_res = platform::windows::ScopedThreadList::collect_other_threads(token.threads, true);
            if (!threads_res) {
                return std::unexpected(threads_res.error());
            }

            LONG err = ::DetourTransactionBegin();
            if (err != NO_ERROR) {
                last_err = err;
                if (err == ERROR_INVALID_OPERATION) {
                    continue;
                }
                return fail(ErrorCode::Conflict, "DetourTransactionBegin", static_cast<std::uint32_t>(err));
            }

            err = ::DetourUpdateThread(::GetCurrentThread());
            bool ok_step = (err == NO_ERROR);
            const char* failed_operation = "DetourUpdateThread";
            for (void* th : threads_res->handles()) {
                if (!ok_step) {
                    break;
                }
                err = ::DetourUpdateThread(static_cast<HANDLE>(th));
                if (err != NO_ERROR && token.threads == ThreadPolicy::SuspendOthersStrict) {
                    ok_step = false;
                    failed_operation = "DetourUpdateThread";
                }
            }

            void* tramp = token.trampoline;
            if (ok_step) {
                failed_operation = "DetourDetach";
                err = ::DetourDetach(&tramp, token.detour);
                ok_step = (err == NO_ERROR);
            }

            if (!ok_step) {
                ::DetourTransactionAbort();
                return fail(ErrorCode::InvalidArgument, failed_operation, static_cast<std::uint32_t>(err));
            }

            err = ::DetourTransactionCommit();
            if (err == NO_ERROR) {
                token.trampoline = nullptr;
                return ok();
            }
            last_err = err;
        }
        return fail(ErrorCode::Conflict, "DetourTransactionCommit", static_cast<std::uint32_t>(last_err));
#else
        return native_inline_hook_backend().detach(token);
#endif
    }
};

} // namespace

HookBackend& default_hook_backend() noexcept {
    static DefaultHookBackend kInstance{};
    return kInstance;
}

namespace detail {

HookCore::HookCore(Address target, void* target_ptr, void* detour_ptr, HookBackend* backend) noexcept
    : target_(target),
      target_ptr_(target_ptr),
      detour_ptr_(detour_ptr),
      active_callable_(target_ptr),
      backend_(backend != nullptr ? backend : &default_hook_backend()),
      installed_(false) {}

HookCore::HookCore(HookCore&& other) noexcept
    : target_(other.target_),
      target_ptr_(std::exchange(other.target_ptr_, nullptr)),
      detour_ptr_(std::exchange(other.detour_ptr_, nullptr)),
      active_callable_(std::exchange(other.active_callable_, nullptr)),
      token_(other.token_),
      backend_(other.backend_),
      installed_(std::exchange(other.installed_, false)) {
    other.token_ = HookToken{};
}

HookCore& HookCore::operator=(HookCore&& other) noexcept {
    if (this != &other) {
        if (installed_) {
            auto detach_status = remove();
            if (!detach_status) {
                diagnostics::notify(token_.observer,
                                    DiagnosticSeverity::Warning,
                                    "Hook",
                                    "Move assignment retained the destination because detaching its hook failed",
                                    detach_status.error());
                return *this;
            }
        }
        target_ = other.target_;
        target_ptr_ = std::exchange(other.target_ptr_, nullptr);
        detour_ptr_ = std::exchange(other.detour_ptr_, nullptr);
        active_callable_ = std::exchange(other.active_callable_, nullptr);
        token_ = other.token_;
        backend_ = other.backend_;
        installed_ = std::exchange(other.installed_, false);
        other.token_ = HookToken{};
    }
    return *this;
}

HookCore::~HookCore() noexcept {
    if (installed_) {
        auto st = remove();
        if (!st) {
            diagnostics::notify(token_.observer,
                                DiagnosticSeverity::Warning,
                                "Hook",
                                "Hook destructor failed to detach hook",
                                st.error());
        }
    }
}

Result<HookCore> HookCore::create(Address target, void* detour, HookBackend* backend) noexcept {
    try {
        if (target.is_null()) {
            return fail(ErrorCode::NullAddress, "Hook::create");
        }
        if (detour == nullptr) {
            return fail(ErrorCode::InvalidArgument, "Hook::create", 0,
                        "Detour function pointer cannot be null");
        }
        const auto detour_value = reinterpret_cast<std::uintptr_t>(detour);
        if (target.value() == static_cast<std::uint64_t>(detour_value)) {
            return fail(ErrorCode::InvalidArgument,
                        "Hook::create",
                        0,
                        "Target and detour function addresses must differ");
        }
        if constexpr (sizeof(void*) == 4) {
            if (target.value() > (std::numeric_limits<std::uintptr_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "Hook::create");
            }
        }

        // Verify that target resides in executable memory of the current process.
        MemoryReader reader{Process::current()};
        auto exec = reader.is_executable(AddressRange{target, 1});
        if (!exec) {
            return std::unexpected(exec.error());
        }
        if (!*exec) {
            return fail(ErrorCode::AccessDenied,
                        "Hook::create",
                        0,
                        "Target address is not executable in the current process");
        }

        const Address detour_address{static_cast<std::uint64_t>(detour_value)};
        auto detour_exec = reader.is_executable(AddressRange{detour_address, 1});
        if (!detour_exec) {
            return std::unexpected(detour_exec.error());
        }
        if (!*detour_exec) {
            return fail(ErrorCode::AccessDenied,
                        "Hook::create",
                        0,
                        "Detour address is not executable in the current process");
        }

        void* const tgt_ptr =
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(target.value()));
        return HookCore{target, tgt_ptr, detour, backend};
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Hook::create");
    } catch (...) {
        return fail(ErrorCode::IoError, "Hook::create", 0,
                    "Hook creation raised an unexpected exception");
    }
}

Status HookCore::install(const HookOptions& options) noexcept {
    if (installed_) {
        return ok();
    }
    if (!is_valid_thread_policy(options.threads)) {
        return fail(ErrorCode::InvalidArgument,
                    "Hook::install",
                    0,
                    "Unknown thread coordination policy");
    }
    if (backend_ == nullptr || !backend_->available()) {
        return fail(ErrorCode::BackendUnavailable,
                    "Hook::install",
                    0,
                    "Hook backend is unavailable");
    }

    // Backends must make attach failure-atomic: an exception or error result
    // must leave the target bytes unchanged and release temporary resources.
    const auto attach_result = [&]() -> Result<HookToken> {
        try {
            return backend_->attach(target_, detour_ptr_, options);
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "Hook::install");
        } catch (...) {
            return fail(ErrorCode::IoError, "Hook::install", 0,
                        "Hook backend raised an unexpected exception during attach");
        }
    }();

    if (!attach_result) {
        diagnostics::notify(options.observer,
                            DiagnosticSeverity::Error,
                            "Hook",
                            "Hook attach failed",
                            attach_result.error());
        return std::unexpected(attach_result.error());
    }

    token_ = *attach_result;
    active_callable_ = token_.trampoline != nullptr ? token_.trampoline : target_ptr_;
    installed_ = true;
    return ok();
}

Status HookCore::remove() noexcept {
    if (!installed_) {
        return ok();
    }
    if (backend_ == nullptr) {
        return fail(ErrorCode::BackendUnavailable, "Hook::remove");
    }

    const auto detach_result = [&]() -> Status {
        try {
            return backend_->detach(token_);
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "Hook::remove");
        } catch (...) {
            return fail(ErrorCode::IoError, "Hook::remove", 0,
                        "Hook backend raised an unexpected exception during detach");
        }
    }();
    if (!detach_result) {
        return detach_result;
    }

    active_callable_ = target_ptr_;
    installed_ = false;
    token_ = HookToken{};
    return ok();
}

void* HookCore::release() noexcept {
    void* const current_fn = active_callable_;
    installed_ = false;
    token_ = HookToken{};
    return current_fn;
}

} // namespace detail

} // namespace tessera
