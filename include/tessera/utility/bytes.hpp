#pragma once

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

namespace tessera::utility {

template <std::integral T>
[[nodiscard]] constexpr T read_le(std::span<const std::byte, sizeof(T)> bytes) noexcept {
    std::array<std::byte, sizeof(T)> tmp{};
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        tmp[i] = bytes[i];
    }
    T val = std::bit_cast<T>(tmp);
    if constexpr (std::endian::native == std::endian::big && sizeof(T) > 1) {
        val = std::byteswap(val);
    }
    return val;
}

template <std::integral T>
constexpr void write_le(T value, std::span<std::byte, sizeof(T)> out) noexcept {
    if constexpr (std::endian::native == std::endian::big && sizeof(T) > 1) {
        value = std::byteswap(value);
    }
    const auto tmp = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out[i] = tmp[i];
    }
}

using Sha256Digest = std::array<std::uint8_t, 32>;

[[nodiscard]] Sha256Digest sha256(std::span<const std::byte> data) noexcept;

[[nodiscard]] std::string sha256_hex(std::span<const std::byte> data);

} // namespace tessera::utility
