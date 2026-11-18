#pragma once

#include <expected>
#include <functional>
#include <type_traits>
#include <utility>

#include "tessera/core/error.hpp"

namespace tessera {

template <class T>
using Result = std::expected<T, Error>;

using Status = Result<void>;

namespace detail {

template <class T>
struct IsResult : std::false_type {};

template <class T>
struct IsResult<Result<T>> : std::true_type {};

template <class T>
inline constexpr bool kIsResultV = IsResult<std::remove_cvref_t<T>>::value;

} // namespace detail

[[nodiscard]] inline constexpr Status ok() noexcept {
    return Status{};
}

[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code,
                                                 std::string_view operation = {},
                                                 std::uint32_t native = 0,
                                                 const char* detail = "") {
    return std::unexpected<Error>(make_error(code, operation, native, detail));
}

[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code,
                                                 std::string_view operation,
                                                 std::uint32_t native,
                                                 std::string detail) {
    return std::unexpected<Error>(make_error(code, operation, native, std::move(detail)));
}

[[nodiscard]] inline constexpr std::unexpected<Error> fail(Error err) noexcept {
    return std::unexpected<Error>(std::move(err));
}

// Pipe (|) operator supporting both monadic (Fn -> Result<U>) and transform (Fn -> U) steps.
template <class T, class Fn>
    requires (!std::is_void_v<T> && std::invocable<Fn, T&&>)
[[nodiscard]] constexpr auto operator|(Result<T>&& res, Fn&& fn) {
    using Ret = std::invoke_result_t<Fn, T&&>;
    if constexpr (detail::kIsResultV<Ret>) {
        return std::move(res).and_then(std::forward<Fn>(fn));
    } else {
        return std::move(res).transform(std::forward<Fn>(fn));
    }
}

template <class T, class Fn>
    requires (!std::is_void_v<T> && std::invocable<Fn, const T&>)
[[nodiscard]] constexpr auto operator|(const Result<T>& res, Fn&& fn) {
    using Ret = std::invoke_result_t<Fn, const T&>;
    if constexpr (detail::kIsResultV<Ret>) {
        return res.and_then(std::forward<Fn>(fn));
    } else {
        return res.transform(std::forward<Fn>(fn));
    }
}

template <class T, class Fn>
    requires (!std::is_void_v<T> && std::invocable<Fn, T&>)
[[nodiscard]] constexpr auto operator|(Result<T>& res, Fn&& fn) {
    using Ret = std::invoke_result_t<Fn, T&>;
    if constexpr (detail::kIsResultV<Ret>) {
        return res.and_then(std::forward<Fn>(fn));
    } else {
        return res.transform(std::forward<Fn>(fn));
    }
}

} // namespace tessera
