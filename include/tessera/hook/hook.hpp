#pragma once

#include <cstdint>
#include <type_traits>
#include <utility>

#include "tessera/core/assert.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"

namespace tessera {

// Thread coordination used while the entry point is updated/restored.
// Strict fails when an enumerated thread cannot be suspended or inspected.
// Coordination uses a one-time snapshot; threads created afterward are not
// covered and this is not an application call-admission gate. Unknown enum
// values are rejected rather than silently downgraded to best effort.
// BestEffort may skip threads that cannot be suspended; callers must provide
// their own quiescence guarantee for those threads. None performs no
// coordination and always requires an externally quiescent patch window.
enum class ThreadPolicy : std::uint8_t {
    SuspendOthersStrict,
    SuspendOthersBestEffort,
    None,
};

struct HookOptions {
    ThreadPolicy threads = ThreadPolicy::SuspendOthersStrict;
    DiagnosticObserver* observer = nullptr;
};

struct HookToken {
    void* target = nullptr;
    void* detour = nullptr;
    void* trampoline = nullptr;
    ThreadPolicy threads = ThreadPolicy::SuspendOthersStrict;
    DiagnosticObserver* observer = nullptr;
    void* backend_data = nullptr; // Backend-owned state; do not read or modify.
};

class HookBackend {
public:
    virtual ~HookBackend() = default;

    // attach() must be failure-atomic: on an error result or exception, the
    // target bytes must remain unchanged and all temporary backend resources
    // must be released. A successful token transfers backend-state ownership
    // to the caller until detach() succeeds.
    // detach() must either succeed and invalidate the token, or fail while
    // leaving the hook and token valid for a safe retry.
    [[nodiscard]] virtual bool available() const noexcept = 0;
    [[nodiscard]] virtual Result<HookToken> attach(Address target,
                                                   void* detour,
                                                   const HookOptions& options) = 0;
    [[nodiscard]] virtual Status detach(HookToken& token) = 0;
};

// The built-in in-process x86/x64 inline backend. It is available independently
// of Microsoft Detours and can be selected explicitly in Hook::create().
[[nodiscard]] HookBackend& native_inline_hook_backend() noexcept;

// Uses Microsoft Detours when TESSERA_WITH_DETOURS=ON; otherwise uses the
// built-in native inline backend.
[[nodiscard]] HookBackend& default_hook_backend() noexcept;

template <class Fn>
concept FunctionPointer = std::is_pointer_v<Fn> && std::is_function_v<std::remove_pointer_t<Fn>>;

namespace detail {

class HookCore {
public:
    HookCore() noexcept = default;

    [[nodiscard]] static Result<HookCore> create(Address target,
                                                 void* detour,
                                                 HookBackend* backend = nullptr) noexcept;

    HookCore(const HookCore&) = delete;
    HookCore& operator=(const HookCore&) = delete;

    HookCore(HookCore&& other) noexcept;
    HookCore& operator=(HookCore&& other) noexcept;

    ~HookCore() noexcept;

    [[nodiscard]] Status install(const HookOptions& options = {}) noexcept;
    [[nodiscard]] Status remove() noexcept;
    [[nodiscard]] void* release() noexcept;

    [[nodiscard]] bool installed() const noexcept { return installed_; }
    [[nodiscard]] Address target() const noexcept { return target_; }
    [[nodiscard]] void* callable() const noexcept { return active_callable_; }

private:
    HookCore(Address target, void* target_ptr, void* detour_ptr, HookBackend* backend) noexcept;

    Address target_{};
    void* target_ptr_ = nullptr;
    void* detour_ptr_ = nullptr;
    void* active_callable_ = nullptr;
    HookToken token_{};
    HookBackend* backend_ = nullptr;
    bool installed_ = false;
};

} // namespace detail

// Move-only typed inline hook wrapper for the current process.
// Before remove() or destruction, stop new calls and wait for in-flight detour
// callbacks/original-trampoline calls to finish. The destructor attempts detach
// but cannot report failure; explicitly call remove() and inspect its result
// before destruction when cleanup failure is possible. If detach fails during
// destruction, the patch may remain active, so keep the detour module and its
// callback state alive for as long as the process can reach that patch.
// Calling original() or operator() is valid immediately after create():
// before install() and after remove() it invokes the target function; while installed it invokes the trampoline.
template <FunctionPointer Fn>
class [[nodiscard]] Hook {
public:
    [[nodiscard]] static Result<Hook> create(Address target,
                                             Fn detour,
                                             HookBackend* backend = nullptr) noexcept {
        auto core_res = detail::HookCore::create(
            target,
            reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(detour)),
            backend);
        if (!core_res) {
            return std::unexpected(core_res.error());
        }
        return Hook{std::move(*core_res)};
    }

    [[nodiscard]] static Result<Hook> create(Fn target,
                                             Fn detour,
                                             HookBackend* backend = nullptr) noexcept {
        return create(
            Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(target))},
            detour,
            backend);
    }

    Hook(const Hook&) = delete;
    Hook& operator=(const Hook&) = delete;
    Hook(Hook&&) noexcept = default;
    Hook& operator=(Hook&&) noexcept = default;
    ~Hook() noexcept = default;

    [[nodiscard]] Status install(HookOptions options = {}) noexcept {
        return core_.install(options);
    }

    [[nodiscard]] Status remove() noexcept { return core_.remove(); }

    // Leaves the hook installed permanently and prevents the destructor from detaching it.
    Fn release() noexcept {
        return reinterpret_cast<Fn>(reinterpret_cast<std::uintptr_t>(core_.release()));
    }

    [[nodiscard]] bool installed() const noexcept { return core_.installed(); }
    [[nodiscard]] Address target() const noexcept { return core_.target(); }

    // Returns a non-owning raw function pointer (the trampoline while installed).
    // It does not pin trampoline memory or participate in call tracking. The
    // caller must quiesce all uses before remove(), destruction, or release of
    // any module/state used by the detour.
    [[nodiscard]] Fn original() const noexcept {
        return reinterpret_cast<Fn>(reinterpret_cast<std::uintptr_t>(core_.callable()));
    }

    // Convenience invocation only; it does not synchronize with remove() or
    // object destruction. Externally serialize lifecycle changes and calls.
    template <class... Args>
        requires std::invocable<Fn, Args...>
    decltype(auto) operator()(Args&&... args) const {
        const Fn fn = original();
        TESSERA_ASSERT(fn != nullptr);
        return fn(std::forward<Args>(args)...);
    }

private:
    explicit Hook(detail::HookCore core) noexcept : core_(std::move(core)) {}

    detail::HookCore core_;
};

} // namespace tessera
