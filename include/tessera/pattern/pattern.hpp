#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>

#include "tessera/core/function_ref.hpp"
#include "tessera/core/result.hpp"

namespace tessera {

struct PatternError {
    std::size_t position = 0;
    std::string_view reason{};
};

template <class T>
concept PatternValue =
    std::is_trivially_copyable_v<T> && std::is_object_v<T> && !std::is_array_v<T> &&
    (std::is_arithmetic_v<T> || std::is_enum_v<T> || std::is_pointer_v<T> ||
     std::has_unique_object_representations_v<T>);

// Represents a byte signature with per-byte bitmasks.
// Independent of Process, Module, or Scanner.
class [[nodiscard]] Pattern {
public:
    static constexpr std::size_t kInlineCapacity = 256;
    static constexpr std::size_t kMaxPatternLength = 256;

    constexpr Pattern() noexcept = default;
    constexpr ~Pattern() noexcept = default;
    constexpr Pattern(const Pattern&) noexcept = default;
    constexpr Pattern& operator=(const Pattern&) noexcept = default;
    constexpr Pattern(Pattern&&) noexcept = default;
    constexpr Pattern& operator=(Pattern&&) noexcept = default;

    [[nodiscard]] static Result<Pattern> parse(std::string_view text,
                                               PatternError* out_error = nullptr);

    [[nodiscard]] static Result<Pattern> from_bytes(std::span<const std::byte> bytes);

    [[nodiscard]] static Result<Pattern> from_code(std::span<const std::byte> bytes,
                                                   std::string_view mask);

    [[nodiscard]] static Result<Pattern> from_text(std::string_view text);

    [[nodiscard]] static Result<Pattern> from_utf16(std::u16string_view text);

    template <PatternValue T>
    [[nodiscard]] static Result<Pattern> from_value(const T& value) {
        const auto raw = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
        return from_bytes(raw);
    }

    [[nodiscard]] Result<Pattern> extended(std::size_t trailing_wildcards) const;

    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }

    [[nodiscard]] constexpr std::span<const std::byte> bytes() const noexcept {
        return {inline_bytes_.data(), size_};
    }

    [[nodiscard]] constexpr std::span<const std::byte> mask() const noexcept {
        return {inline_mask_.data(), size_};
    }

    [[nodiscard]] constexpr std::optional<std::size_t> anchor_index() const noexcept {
        return has_anchor_ ? std::optional<std::size_t>{anchor_} : std::nullopt;
    }

    // Derived metadata keeps Pattern's object layout and existing ABI unchanged.
    [[nodiscard]] constexpr std::size_t leading_wildcards() const noexcept {
        std::size_t n = 0;
        while (n < size_ && inline_mask_[n] == std::byte{0}) {
            ++n;
        }
        return n;
    }

    [[nodiscard]] constexpr std::size_t trailing_wildcards() const noexcept {
        std::size_t n = 0;
        while (n < size_ && inline_mask_[size_ - n - 1] == std::byte{0}) {
            ++n;
        }
        return n;
    }

    [[nodiscard]] constexpr bool is_exact() const noexcept {
        if (size_ == 0) {
            return false;
        }
        for (std::size_t i = 0; i < size_; ++i) {
            if (inline_mask_[i] != std::byte{0xFF}) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] constexpr bool is_byte_mask_only() const noexcept {
        for (std::size_t i = 0; i < size_; ++i) {
            if (inline_mask_[i] != std::byte{0} &&
                inline_mask_[i] != std::byte{0xFF}) {
                return false;
            }
        }
        return size_ != 0;
    }

    [[nodiscard]] constexpr bool is_nibble_masked() const noexcept {
        for (std::size_t i = 0; i < size_; ++i) {
            if (inline_mask_[i] != std::byte{0} &&
                inline_mask_[i] != std::byte{0xFF}) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] constexpr std::optional<std::size_t> secondary_anchor_index() const noexcept {
        if (!has_anchor_) {
            return std::nullopt;
        }
        std::optional<std::size_t> best{};
        int best_score = 99;
        for (std::size_t i = 0; i < size_; ++i) {
            if (i == anchor_ || inline_mask_[i] != std::byte{0xFF}) {
                continue;
            }
            const int score = byte_commonness(inline_bytes_[i]);
            if (score < best_score) {
                best = i;
                best_score = score;
                if (score == 0) {
                    break;
                }
            }
        }
        return best;
    }

    [[nodiscard]] constexpr bool matches(std::span<const std::byte> at) const noexcept {
        if (size_ == 0 || at.size() < size_) {
            return false;
        }
        const auto b = bytes();
        const auto m = mask();
        for (std::size_t i = 0; i < size_; ++i) {
            if ((at[i] & m[i]) != b[i]) {
                return false;
            }
        }
        return true;
    }

    // Searches `data` and invokes `on_match(offset)` for each match where offset < start_limit.
    // If `on_match` returns false, stops searching early.
    void search(std::span<const std::byte> data,
                std::size_t start_limit,
                FunctionRef<bool(std::size_t)> on_match) const;

    // Compile-time parser helper used by operator""_sig
    [[nodiscard]] static consteval Pattern parse_consteval(std::string_view text) {
        Pattern p;
        const std::size_t n = text.size();
        std::size_t i = 0;
        while (i < n) {
            while (i < n && is_space(text[i])) {
                ++i;
            }
            if (i == n) {
                break;
            }
            std::size_t j = i;
            while (j < n && !is_space(text[j])) {
                ++j;
            }
            const std::string_view tok = text.substr(i, j - i);
            i = j;

            if (tok == "?" || tok == "??" || tok == "*" || tok == "**") {
                if (p.size_ >= kInlineCapacity) {
                    throw "Pattern literal exceeds compile-time inline capacity";
                }
                p.push_inline(std::byte{0}, std::byte{0});
                continue;
            }
            if ((tok.size() % 2) != 0) {
                throw "Invalid odd-length token in pattern literal";
            }
            for (std::size_t k = 0; k < tok.size(); k += 2) {
                std::uint8_t hv = 0, hm = 0, lv = 0, lm = 0;
                if (!parse_nibble(tok[k], hv, hm) || !parse_nibble(tok[k + 1], lv, lm)) {
                    throw "Invalid hex or wildcard character in pattern literal";
                }
                if (p.size_ >= kInlineCapacity) {
                    throw "Pattern literal exceeds compile-time inline capacity";
                }
                const auto val = static_cast<std::byte>((hv << 4) | lv);
                const auto msk = static_cast<std::byte>((hm << 4) | lm);
                p.push_inline(val & msk, msk);
            }
        }
        if (!p.finalize_anchor()) {
            throw "Pattern literal must contain at least one constrained bit";
        }
        return p;
    }

private:
    static constexpr bool is_space(char c) noexcept {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    static constexpr bool parse_nibble(char c, std::uint8_t& v, std::uint8_t& m) noexcept {
        if (c >= '0' && c <= '9') {
            v = static_cast<std::uint8_t>(c - '0');
            m = 0x0Fu;
            return true;
        }
        if (c >= 'a' && c <= 'f') {
            v = static_cast<std::uint8_t>(c - 'a' + 10);
            m = 0x0Fu;
            return true;
        }
        if (c >= 'A' && c <= 'F') {
            v = static_cast<std::uint8_t>(c - 'A' + 10);
            m = 0x0Fu;
            return true;
        }
        if (c == '?') {
            v = 0;
            m = 0;
            return true;
        }
        return false;
    }

    static constexpr int byte_commonness(std::byte b) noexcept {
        switch (std::to_integer<std::uint8_t>(b)) {
            case 0x00:
            case 0xFF:
                return 2;
            case 0x48:
            case 0x8B:
            case 0x89:
            case 0x0F:
            case 0xE8:
            case 0xCC:
            case 0x4C:
            case 0x24:
            case 0x05:
            case 0x01:
            case 0x8D:
            case 0x83:
            case 0xC0:
                return 1;
            default:
                return 0;
        }
    }

    constexpr void push_inline(std::byte v, std::byte m) noexcept {
        inline_bytes_[size_] = v & m;
        inline_mask_[size_] = m;
        ++size_;
    }

    constexpr bool finalize_anchor() noexcept {
        if (size_ == 0) {
            return false;
        }
        const auto b = bytes();
        const auto m = mask();
        bool constrained = false;
        for (std::size_t i = 0; i < size_; ++i) {
            if (m[i] != std::byte{0}) {
                constrained = true;
                break;
            }
        }
        if (!constrained) {
            return false;
        }

        has_anchor_ = false;
        anchor_ = 0;
        int best_score = 99;
        for (std::size_t i = 0; i < size_; ++i) {
            if (m[i] != std::byte{0xFF}) {
                continue;
            }
            const int score = byte_commonness(b[i]);
            if (score < best_score) {
                best_score = score;
                anchor_ = i;
                has_anchor_ = true;
                if (score == 0) {
                    break;
                }
            }
        }
        return true;
    }

    static Result<Pattern> build_from_spans(std::span<const std::byte> raw_bytes,
                                            std::span<const std::byte> raw_mask,
                                            std::string_view op_name);

    std::array<std::byte, kInlineCapacity> inline_bytes_{};
    std::array<std::byte, kInlineCapacity> inline_mask_{};
    std::size_t size_ = 0;
    std::size_t anchor_ = 0;
    bool has_anchor_ = false;
};

namespace literals {

[[nodiscard]] consteval Pattern operator""_sig(const char* text, std::size_t len) {
    return Pattern::parse_consteval(std::string_view{text, len});
}

} // namespace literals

using literals::operator""_sig;

} // namespace tessera
