#pragma once

#include <type_traits>
#include <utility>

namespace tessera {

template <class E>
struct EnableEnumFlags : std::false_type {};

template <class E>
concept FlagEnum = std::is_enum_v<E> && EnableEnumFlags<E>::value;

template <FlagEnum E>
[[nodiscard]] constexpr E operator|(E lhs, E rhs) noexcept {
    return static_cast<E>(std::to_underlying(lhs) | std::to_underlying(rhs));
}

template <FlagEnum E>
[[nodiscard]] constexpr E operator&(E lhs, E rhs) noexcept {
    return static_cast<E>(std::to_underlying(lhs) & std::to_underlying(rhs));
}

template <FlagEnum E>
[[nodiscard]] constexpr E operator^(E lhs, E rhs) noexcept {
    return static_cast<E>(std::to_underlying(lhs) ^ std::to_underlying(rhs));
}

template <FlagEnum E>
[[nodiscard]] constexpr E operator~(E val) noexcept {
    return static_cast<E>(~std::to_underlying(val));
}

template <FlagEnum E>
constexpr E& operator|=(E& lhs, E rhs) noexcept {
    lhs = lhs | rhs;
    return lhs;
}

template <FlagEnum E>
constexpr E& operator&=(E& lhs, E rhs) noexcept {
    lhs = lhs & rhs;
    return lhs;
}

template <FlagEnum E>
constexpr E& operator^=(E& lhs, E rhs) noexcept {
    lhs = lhs ^ rhs;
    return lhs;
}

template <FlagEnum E>
[[nodiscard]] constexpr bool has_flag(E value, E flag) noexcept {
    const auto f = std::to_underlying(flag);
    return f != 0 && (std::to_underlying(value) & f) == f;
}

template <FlagEnum E>
[[nodiscard]] constexpr bool any_flag(E value, E mask) noexcept {
    return (std::to_underlying(value) & std::to_underlying(mask)) != 0;
}

} // namespace tessera

#define TESSERA_ENABLE_ENUM_FLAGS(EnumType)                                                        \
    template <>                                                                                    \
    struct tessera::EnableEnumFlags<EnumType> : std::true_type {}
