#pragma once

#include <type_traits>
#include <utility>

namespace tessera::utility {

template <class F>
class [[nodiscard]] ScopeGuard {
public:
    explicit constexpr ScopeGuard(F&& fn) noexcept(std::is_nothrow_move_constructible_v<F>)
        : fn_(std::forward<F>(fn)), active_(true) {}

    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;

    constexpr ScopeGuard(ScopeGuard&& other) noexcept(std::is_nothrow_move_constructible_v<F>)
        : fn_(std::move(other.fn_)), active_(std::exchange(other.active_, false)) {}

    constexpr ~ScopeGuard() noexcept {
        if (active_) {
            fn_();
        }
    }

    constexpr void dismiss() noexcept { active_ = false; }

private:
    F fn_;
    bool active_ = false;
};

template <class F>
[[nodiscard]] constexpr ScopeGuard<std::decay_t<F>> make_scope_guard(F&& fn) noexcept(
    std::is_nothrow_constructible_v<std::decay_t<F>, F&&>) {
    return ScopeGuard<std::decay_t<F>>(std::forward<F>(fn));
}

} // namespace tessera::utility
