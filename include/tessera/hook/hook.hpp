#pragma once

#include <atomic>
#include <cstdint>
#include <exception>
#include <mutex>
#include <shared_mutex>
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
    class CallableLease {
    public:
        CallableLease(const CallableLease&) = delete;
        CallableLease& operator=(const CallableLease&) = delete;
        CallableLease(CallableLease&&) = delete;
        CallableLease& operator=(CallableLease&&) = delete;

        ~CallableLease() noexcept {
            if (active_lease_frame_ != &frame_) {
                std::terminate();
            }
            active_lease_frame_ = frame_.previous;
        }

        [[nodiscard]] void* get() const noexcept { return callable_; }

    private:
        struct Frame {
            const HookCore* owner = nullptr;
            Frame* previous = nullptr;
        };

        friend class HookCore;
        explicit CallableLease(const HookCore& owner) {
            bool already_leased = false;
            for (Frame* frame = active_lease_frame_; frame != nullptr;
                 frame = frame->previous) {
                if (frame->owner == &owner) {
                    already_leased = true;
                    break;
                }
            }

            // std::shared_mutex is not recursively lockable. A nested
            // invocation on this thread is already protected by its outer
            // lease, so it must not acquire the same shared mutex again.
            if (!already_leased) {
                lock_ = std::shared_lock<std::shared_mutex>{owner.lifecycle_mutex_};
            }
            callable_ = owner.active_callable_.load(std::memory_order_acquire);

            frame_.owner = &owner;
            frame_.previous = active_lease_frame_;
            active_lease_frame_ = &frame_;
        }

        std::shared_lock<std::shared_mutex> lock_{};
        void* callable_ = nullptr;
        Frame frame_{};
        inline static thread_local Frame* active_lease_frame_ = nullptr;

        [[nodiscard]] static bool is_active_on_current_thread(
            const HookCore& owner) noexcept {
            for (Frame* frame = active_lease_frame_; frame != nullptr;
                 frame = frame->previous) {
                if (frame->owner == &owner) {
                    return true;
                }
            }
            return false;
        }
    };

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

    // A lease keeps the current callable valid until the returned object is
    // destroyed. remove(), install(), and release() take the exclusive side
    // of the same lock and therefore wait for leased invocations to finish.
    [[nodiscard]] CallableLease acquire_callable() const {
        return CallableLease{*this};
    }
    [[nodiscard]] bool installed() const noexcept {
        return installed_.load(std::memory_order_acquire);
    }
    [[nodiscard]] Address target() const noexcept { return target_; }

    // Unsafe non-owning snapshot used only by original(); callers must
    // externally quiesce it before detach or release.
    [[nodiscard]] void* callable() const noexcept { return active_callable_.load(std::memory_order_acquire); }

private:
    HookCore(Address target, void* target_ptr, void* detour_ptr, HookBackend* backend) noexcept;

    mutable std::shared_mutex lifecycle_mutex_{};
    Address target_{};
    void* target_ptr_ = nullptr;
    void* detour_ptr_ = nullptr;
    std::atomic<void*> active_callable_{nullptr};
    HookToken token_{};
    HookBackend* backend_ = nullptr;
    std::atomic<bool> installed_{false};
};

} // namespace detail

// Move-only typed inline hook wrapper for the current process.
// operator() holds an internal call lease: remove(), install(), and release()
// wait for calls made through that operator to finish before changing the
// callable/trampoline lifetime. Direct target calls and raw pointers returned
// by original() bypass that lease; the host must stop new entries and drain
// in-flight detour callbacks and raw trampoline calls before detach or unload.
// The destructor attempts detach but cannot report failure; explicitly call
// remove() and inspect its result before destruction when cleanup failure is
// possible. If detach fails during destruction, the patch may remain active,
// so keep the detour module and callback state alive.
// Calling original() or operator() is valid immediately after create():
// before install() and after remove() it invokes the target; while installed
// it invokes the trampoline. Concurrent destruction or moves still require
// external synchronization with all users of the Hook object.
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
    // Calling this from the hook's own leased operator() invocation returns
    // nullptr and retains normal ownership instead of self-deadlocking.
    Fn release() noexcept {
        return reinterpret_cast<Fn>(reinterpret_cast<std::uintptr_t>(core_.release()));
    }

    [[nodiscard]] bool installed() const noexcept { return core_.installed(); }
    [[nodiscard]] Address target() const noexcept { return core_.target(); }

    // Explicit call lease for code that needs to retain a callable across a
    // multi-step operation. The lease is non-copyable and non-movable so its
    // thread-local nesting frame remains valid. It must not be used to export
    // the pointer beyond the lease lifetime; direct target entries and escaped
    // pointers remain outside Tessera's call tracking.
    class ScopedCallable {
    public:
        ScopedCallable(const ScopedCallable&) = delete;
        ScopedCallable& operator=(const ScopedCallable&) = delete;
        ScopedCallable(ScopedCallable&&) = delete;
        ScopedCallable& operator=(ScopedCallable&&) = delete;

        [[nodiscard]] Fn get() const noexcept {
            return reinterpret_cast<Fn>(reinterpret_cast<std::uintptr_t>(lease_.get()));
        }

    private:
        friend class Hook;
        explicit ScopedCallable(const detail::HookCore& core)
            : lease_(core.acquire_callable()) {}
        detail::HookCore::CallableLease lease_;
    };

    // Acquires the lifecycle lease before returning the current callable.
    // remove(), install(), and release() wait until this scope ends.
    [[nodiscard]] ScopedCallable acquire() const {
        return ScopedCallable{core_};
    }

    // Returns a non-owning raw function pointer (the trampoline while installed).
    // It does not pin trampoline memory or participate in call tracking. The
    // caller must quiesce all uses before remove(), destruction, or release of
    // any module/state used by the detour.
    [[nodiscard]] Fn original() const noexcept {
        return reinterpret_cast<Fn>(reinterpret_cast<std::uintptr_t>(core_.callable()));
    }

    // This invocation holds a lease for the full duration of the call, so a
    // concurrent remove()/release() cannot free the trampoline until it ends.
    // Calls made through a copied raw pointer from original() are not tracked.
    template <class... Args>
        requires std::invocable<Fn, Args...>
    decltype(auto) operator()(Args&&... args) const {
        auto lease = core_.acquire_callable();
        const Fn fn = reinterpret_cast<Fn>(
            reinterpret_cast<std::uintptr_t>(lease.get()));
        TESSERA_ASSERT(fn != nullptr);
        return fn(std::forward<Args>(args)...);
    }

private:
    explicit Hook(detail::HookCore core) noexcept : core_(std::move(core)) {}

    detail::HookCore core_;
};

} // namespace tessera
