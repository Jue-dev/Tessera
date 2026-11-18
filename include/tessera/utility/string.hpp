#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tessera::utility {

[[nodiscard]] constexpr bool is_ascii_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

[[nodiscard]] constexpr char ascii_char_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] constexpr char ascii_char_upper(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

[[nodiscard]] constexpr std::string_view trim_left(std::string_view sv) noexcept {
    std::size_t i = 0;
    while (i < sv.size() && is_ascii_space(sv[i])) {
        ++i;
    }
    return sv.substr(i);
}

[[nodiscard]] constexpr std::string_view trim_right(std::string_view sv) noexcept {
    std::size_t len = sv.size();
    while (len > 0 && is_ascii_space(sv[len - 1])) {
        --len;
    }
    return sv.substr(0, len);
}

[[nodiscard]] constexpr std::string_view trim(std::string_view sv) noexcept {
    return trim_right(trim_left(sv));
}

[[nodiscard]] inline std::string ascii_to_lower(std::string_view sv) {
    std::string out(sv);
    for (char& c : out) {
        c = ascii_char_lower(c);
    }
    return out;
}

[[nodiscard]] inline std::string ascii_to_upper(std::string_view sv) {
    std::string out(sv);
    for (char& c : out) {
        c = ascii_char_upper(c);
    }
    return out;
}

[[nodiscard]] constexpr bool ascii_iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_char_lower(a[i]) != ascii_char_lower(b[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] constexpr bool ascii_icontains(std::string_view haystack,
                                             std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    for (std::size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        if (ascii_iequals(haystack.substr(i, needle.size()), needle)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] inline std::vector<std::string_view> split(std::string_view sv,
                                                         char delimiter,
                                                         bool skip_empty = false) {
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    while (start <= sv.size()) {
        const std::size_t pos = sv.find(delimiter, start);
        const std::size_t end = (pos == std::string_view::npos) ? sv.size() : pos;
        const std::string_view tok = sv.substr(start, end - start);
        if (!skip_empty || !tok.empty()) {
            parts.push_back(tok);
        }
        if (pos == std::string_view::npos) {
            break;
        }
        start = pos + 1;
    }
    return parts;
}

} // namespace tessera::utility
