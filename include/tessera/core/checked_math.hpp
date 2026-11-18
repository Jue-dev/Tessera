#pragma once

#include <concepts>
#include <cstdint>
#include <limits>

#include "tessera/core/result.hpp"

namespace tessera {

template <std::unsigned_integral U>
[[nodiscard]] constexpr Result<U> checked_add(U a, U b) noexcept {
    if (b > (std::numeric_limits<U>::max)() - a) [[unlikely]] {
        return std::unexpected(Error{
            .code = ErrorCode::AddressOverflow,
            .native = 0,
            .operation = "checked_add",
            .detail = {},
        });
    }
    return static_cast<U>(a + b);
}

template <std::unsigned_integral U>
[[nodiscard]] constexpr Result<U> checked_sub(U a, U b) noexcept {
    if (b > a) [[unlikely]] {
        return std::unexpected(Error{
            .code = ErrorCode::AddressOverflow,
            .native = 0,
            .operation = "checked_sub",
            .detail = {},
        });
    }
    return static_cast<U>(a - b);
}

template <std::unsigned_integral U>
[[nodiscard]] constexpr Result<U> checked_mul(U a, U b) noexcept {
    if (a != 0 && b > (std::numeric_limits<U>::max)() / a) [[unlikely]] {
        return std::unexpected(Error{
            .code = ErrorCode::AddressOverflow,
            .native = 0,
            .operation = "checked_mul",
            .detail = {},
        });
    }
    return static_cast<U>(a * b);
}

template <std::unsigned_integral U>
[[nodiscard]] constexpr Result<U> checked_offset(U base, std::int64_t delta) noexcept {
    if (delta >= 0) {
        const auto udelta = static_cast<std::uint64_t>(delta);
        if (udelta > static_cast<std::uint64_t>((std::numeric_limits<U>::max)())) [[unlikely]] {
            return std::unexpected(Error{
                .code = ErrorCode::AddressOverflow,
                .native = 0,
                .operation = "checked_offset",
                .detail = {},
            });
        }
        return checked_add<U>(base, static_cast<U>(udelta));
    }

    // Careful: avoid UB when delta == INT64_MIN
    const auto mag = static_cast<std::uint64_t>(-(delta + 1)) + 1ULL;
    if (mag > static_cast<std::uint64_t>(base)) [[unlikely]] {
        return std::unexpected(Error{
            .code = ErrorCode::AddressOverflow,
            .native = 0,
            .operation = "checked_offset",
            .detail = {},
        });
    }
    return static_cast<U>(base - static_cast<U>(mag));
}

} // namespace tessera
