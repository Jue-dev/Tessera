#pragma once

#include <string>
#include <string_view>

#include "tessera/core/result.hpp"

namespace tessera::encoding {

// Strictly validates whether `text` is well-formed UTF-8 (rejects overlong encodings, surrogates, > U+10FFFF).
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

// Strictly validates whether `text` is well-formed UTF-16 (rejects unpaired high/low surrogates).
[[nodiscard]] bool is_valid_utf16(std::u16string_view text) noexcept;

// Strict UTF-8 -> UTF-16 conversion. Returns ErrorCode::ParseError on malformed sequences.
[[nodiscard]] Result<std::u16string> utf8_to_utf16(std::string_view utf8);

// Strict UTF-16 -> UTF-8 conversion. Returns ErrorCode::ParseError on unpaired surrogates.
[[nodiscard]] Result<std::string> utf16_to_utf8(std::u16string_view utf16);

} // namespace tessera::encoding
