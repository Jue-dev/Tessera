#pragma once

#include <concepts>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

#include "tessera/core/assert.hpp"

namespace tessera {

template <class Signature>
class FunctionRef;

template <class R, class... Args>
class FunctionRef<R(Args...)> {
public:
    constexpr FunctionRef() noexcept = default;
    constexpr FunctionRef(std::nullptr_t) noexcept {}

    template <class F>
        requires (!std::same_as<std::remove_cvref_t<F>, FunctionRef> &&
                  std::is_invocable_r_v<R, F&&, Args...>)
    constexpr FunctionRef(F&& callable) noexcept
        : obj_(const_cast<void*>(static_cast<const void*>(std::addressof(callable)))),
          callback_([](void* obj, Args... args) -> R {
              return std::invoke(*static_cast<std::add_pointer_t<F>>(obj),
                                 std::forward<Args>(args)...);
          }) {}

    constexpr FunctionRef(R (*fn)(Args...)) noexcept
        : obj_(reinterpret_cast<void*>(fn)),
          callback_(fn ? [](void* obj, Args... args) -> R {
              return reinterpret_cast<R (*)(Args...)>(obj)(std::forward<Args>(args)...);
          } : nullptr) {}

    [[nodiscard]] constexpr bool valid() const noexcept { return callback_ != nullptr; }
    constexpr explicit operator bool() const noexcept { return valid(); }

    constexpr R operator()(Args... args) const {
        TESSERA_ASSERT(callback_ != nullptr);
        return callback_(obj_, std::forward<Args>(args)...);
    }

private:
    void* obj_ = nullptr;
    R (*callback_)(void*, Args...) = nullptr;
};

} // namespace tessera
