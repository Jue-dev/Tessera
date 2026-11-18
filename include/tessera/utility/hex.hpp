#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"

namespace tessera::hex {

struct HexDecodeError {
    std::size_t position = 0;
    std::string_view reason{};
};

[[nodiscard]] std::string encode(std::span<const std::byte> bytes, bool uppercase = true);

// Strictly decodes hex text (optional whitespace allowed between byte pairs, no invalid characters skipped).
[[nodiscard]] Result<std::vector<std::byte>> decode(std::string_view hex_text,
                                                    HexDecodeError* out_error = nullptr);

// Strictly parses an unsigned 64-bit hex string (with or without leading "0x"/"0X").
[[nodiscard]] Result<std::uint64_t> parse_u64(std::string_view text);

// Formats a 64-bit integer as "0x..." hex string.
[[nodiscard]] std::string format_u64(std::uint64_t value,
                                     std::size_t min_digits = 1,
                                     bool include_prefix = true);

} // namespace tessera::hex
