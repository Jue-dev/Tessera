#include "tessera/pattern/pattern.hpp"

#include <cstring>
#include <format>
#include <new>
#include <vector>

namespace tessera {

Result<Pattern> Pattern::build_from_spans(std::span<const std::byte> raw_bytes,
                                          std::span<const std::byte> raw_mask,
                                          std::string_view op_name) {
    if (raw_bytes.empty() || raw_bytes.size() != raw_mask.size()) {
        return fail(ErrorCode::InvalidPattern, op_name, 0, "Pattern cannot be empty");
    }
    if (raw_bytes.size() > kMaxPatternLength) {
        return fail(ErrorCode::InvalidPattern,
                    op_name,
                    0,
                    "Pattern length exceeds kMaxPatternLength");
    }

    Pattern p;
    p.size_ = raw_bytes.size();
    for (std::size_t i = 0; i < p.size_; ++i) {
        p.inline_bytes_[i] = raw_bytes[i] & raw_mask[i];
        p.inline_mask_[i] = raw_mask[i];
    }

    if (!p.finalize_anchor()) {
        return fail(ErrorCode::InvalidPattern,
                    op_name,
                    0,
                    "Pattern must contain at least one constrained bit");
    }
    return p;
}

Result<Pattern> Pattern::parse(std::string_view text, PatternError* out_error) {
    auto report_err = [&](std::size_t pos, std::string_view reason) {
        if (out_error != nullptr) {
            *out_error = PatternError{.position = pos, .reason = reason};
        }
        return fail(ErrorCode::InvalidPattern,
                    "Pattern::parse",
                    0,
                    std::format("at offset {}: {}", pos, reason));
    };

    try {
        std::vector<std::byte> bytes_vec;
        std::vector<std::byte> mask_vec;

        const std::size_t n = text.size();
        std::size_t i = 0;
        while (i < n) {
            while (i < n && is_space(text[i])) {
                ++i;
            }
            if (i == n) {
                break;
            }
            const std::size_t token_start = i;
            std::size_t j = i;
            while (j < n && !is_space(text[j])) {
                ++j;
            }
            const std::string_view tok = text.substr(i, j - i);
            i = j;

            if (tok == "?" || tok == "??" || tok == "*" || tok == "**") {
                if (bytes_vec.size() >= kMaxPatternLength) {
                    return report_err(token_start, "Pattern exceeds maximum allowed length");
                }
                bytes_vec.push_back(std::byte{0});
                mask_vec.push_back(std::byte{0});
                continue;
            }

            if ((tok.size() % 2) != 0) {
                return report_err(token_start, "Hex token must have an even number of characters");
            }

            for (std::size_t k = 0; k < tok.size(); k += 2) {
                std::uint8_t hv = 0, hm = 0, lv = 0, lm = 0;
                if (!parse_nibble(tok[k], hv, hm)) {
                    return report_err(token_start + k, "Invalid high nibble character");
                }
                if (!parse_nibble(tok[k + 1], lv, lm)) {
                    return report_err(token_start + k + 1, "Invalid low nibble character");
                }
                if (bytes_vec.size() >= kMaxPatternLength) {
                    return report_err(token_start + k, "Pattern exceeds maximum allowed length");
                }
                const auto val = static_cast<std::byte>((hv << 4) | lv);
                const auto msk = static_cast<std::byte>((hm << 4) | lm);
                bytes_vec.push_back(val & msk);
                mask_vec.push_back(msk);
            }
        }

        if (bytes_vec.empty()) {
            return report_err(0, "Pattern string is empty");
        }

        auto res = build_from_spans(bytes_vec, mask_vec, "Pattern::parse");
        if (!res) {
            return report_err(0, "Pattern cannot consist solely of wildcards");
        }
        return res;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Pattern::parse");
    }
}

Result<Pattern> Pattern::from_bytes(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return fail(ErrorCode::InvalidPattern, "Pattern::from_bytes", 0, "Byte span is empty");
    }
    if (bytes.size() > kMaxPatternLength) {
        return fail(ErrorCode::InvalidPattern,
                    "Pattern::from_bytes",
                    0,
                    "Byte span exceeds kMaxPatternLength");
    }
    try {
        std::vector<std::byte> full_mask(bytes.size(), std::byte{0xFF});
        return build_from_spans(bytes, full_mask, "Pattern::from_bytes");
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Pattern::from_bytes");
    }
}

Result<Pattern> Pattern::from_code(std::span<const std::byte> bytes, std::string_view mask) {
    if (mask.empty() || bytes.size() != mask.size()) {
        return fail(ErrorCode::InvalidPattern,
                    "Pattern::from_code",
                    0,
                    "Bytes and mask must be non-empty and of equal length");
    }
    if (mask.size() > kMaxPatternLength) {
        return fail(ErrorCode::InvalidPattern,
                    "Pattern::from_code",
                    0,
                    "Pattern length exceeds kMaxPatternLength");
    }
    try {
        std::vector<std::byte> mask_bytes(mask.size());
        for (std::size_t i = 0; i < mask.size(); ++i) {
            const char c = mask[i];
            if (c == 'x' || c == 'X') {
                mask_bytes[i] = std::byte{0xFF};
            } else if (c == '?' || c == '.') {
                mask_bytes[i] = std::byte{0x00};
            } else {
                return fail(ErrorCode::InvalidPattern,
                            "Pattern::from_code",
                            0,
                            "Mask contains invalid character (expected 'x', '?', or '.')");
            }
        }
        return build_from_spans(bytes, mask_bytes, "Pattern::from_code");
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Pattern::from_code");
    }
}

Result<Pattern> Pattern::from_text(std::string_view text) {
    if (text.empty()) {
        return fail(ErrorCode::InvalidPattern, "Pattern::from_text", 0, "Text is empty");
    }
    return from_bytes(std::as_bytes(std::span<const char>(text.data(), text.size())));
}

Result<Pattern> Pattern::from_utf16(std::u16string_view text) {
    if (text.empty()) {
        return fail(ErrorCode::InvalidPattern, "Pattern::from_utf16", 0, "UTF-16 text is empty");
    }
    if (text.size() * 2 > kMaxPatternLength) {
        return fail(ErrorCode::InvalidPattern,
                    "Pattern::from_utf16",
                    0,
                    "UTF-16 text exceeds kMaxPatternLength");
    }
    try {
        std::vector<std::byte> raw;
        raw.reserve(text.size() * 2);
        for (const char16_t ch : text) {
            const auto u = static_cast<std::uint16_t>(ch);
            raw.push_back(static_cast<std::byte>(u & 0xFFu));
            raw.push_back(static_cast<std::byte>((u >> 8) & 0xFFu));
        }
        return from_bytes(raw);
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Pattern::from_utf16");
    }
}

Result<Pattern> Pattern::extended(std::size_t trailing_wildcards) const {
    if (empty()) {
        return fail(ErrorCode::InvalidPattern, "Pattern::extended", 0, "Base pattern is empty");
    }
    if (trailing_wildcards == 0) {
        return *this;
    }
    if (size_ + trailing_wildcards > kMaxPatternLength || size_ + trailing_wildcards < size_) {
        return fail(ErrorCode::InvalidPattern,
                    "Pattern::extended",
                    0,
                    "Extended pattern exceeds kMaxPatternLength");
    }
    try {
        const auto cur_b = bytes();
        const auto cur_m = mask();
        std::vector<std::byte> new_b(cur_b.begin(), cur_b.end());
        std::vector<std::byte> new_m(cur_m.begin(), cur_m.end());
        new_b.insert(new_b.end(), trailing_wildcards, std::byte{0});
        new_m.insert(new_m.end(), trailing_wildcards, std::byte{0});
        return build_from_spans(new_b, new_m, "Pattern::extended");
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Pattern::extended");
    }
}

void Pattern::search(std::span<const std::byte> data,
                     std::size_t start_limit,
                     FunctionRef<bool(std::size_t)> on_match) const {
    if (size_ == 0 || data.size() < size_ || !on_match) {
        return;
    }
    const std::size_t limit = (std::min)(start_limit, data.size() - size_ + 1);
    const auto pat_bytes = bytes();
    const std::byte* raw = data.data();

    if (has_anchor_) {
        const auto secondary = secondary_anchor_index();
        const int key = static_cast<int>(std::to_integer<unsigned char>(pat_bytes[anchor_]));
        std::size_t off = 0;
        while (off < limit) {
            const void* hit = std::memchr(raw + off + anchor_, key, limit - off);
            if (hit == nullptr) {
                return;
            }
            const auto hit_idx =
                static_cast<std::size_t>(static_cast<const std::byte*>(hit) - raw);
            if (hit_idx < anchor_) {
                return;
            }
            const std::size_t candidate = hit_idx - anchor_;
            const bool secondary_matches =
                !secondary.has_value() ||
                data[candidate + *secondary] == pat_bytes[*secondary];
            const bool full_match =
                secondary_matches &&
                (is_exact()
                     ? std::memcmp(data.data() + candidate, pat_bytes.data(), size_) == 0
                     : matches(data.subspan(candidate, size_)));
            if (full_match) {
                if (!on_match(candidate)) {
                    return;
                }
            }
            off = candidate + 1;
        }
    } else {
        for (std::size_t off = 0; off < limit; ++off) {
            if (matches(data.subspan(off, size_))) {
                if (!on_match(off)) {
                    return;
                }
            }
        }
    }
}

} // namespace tessera
