#include "tessera/utility/utility.hpp"

#include <Windows.h>
#include <ShlObj.h>

#include <array>
#include <bit>
#include <cstring>
#include <format>
#include <new>

namespace tessera {

namespace utility {

namespace {

constexpr std::array<std::uint32_t, 64> kSha256K{
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr void sha256_transform(std::array<std::uint32_t, 8>& state,
                                const std::uint8_t block[64]) noexcept {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 =
            std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 =
            std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
        const std::uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

} // namespace

Sha256Digest sha256(std::span<const std::byte> data) noexcept {
    std::array<std::uint32_t, 8> state{
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

    const auto* raw = reinterpret_cast<const std::uint8_t*>(data.data());
    const std::size_t total_len = data.size();
    std::size_t offset = 0;
    while (total_len - offset >= 64) {
        sha256_transform(state, raw + offset);
        offset += 64;
    }

    std::uint8_t tail[128]{};
    const std::size_t rem = total_len - offset;
    if (rem > 0) {
        std::memcpy(tail, raw + offset, rem);
    }
    tail[rem] = 0x80u;

    const std::size_t pad_blocks = (rem < 56) ? 1 : 2;
    const std::uint64_t bit_len = static_cast<std::uint64_t>(total_len) * 8ULL;
    const std::size_t len_pos = pad_blocks * 64 - 8;
    for (std::size_t i = 0; i < 8; ++i) {
        tail[len_pos + i] = static_cast<std::uint8_t>((bit_len >> ((7 - i) * 8)) & 0xFFu);
    }

    sha256_transform(state, tail);
    if (pad_blocks == 2) {
        sha256_transform(state, tail + 64);
    }

    Sha256Digest digest{};
    for (std::size_t i = 0; i < 8; ++i) {
        digest[i * 4 + 0] = static_cast<std::uint8_t>((state[i] >> 24) & 0xFFu);
        digest[i * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 16) & 0xFFu);
        digest[i * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 8) & 0xFFu);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(state[i] & 0xFFu);
    }
    return digest;
}

std::string sha256_hex(std::span<const std::byte> data) {
    const auto d = sha256(data);
    return hex::encode(std::as_bytes(std::span<const std::uint8_t>(d)), false);
}

Result<std::filesystem::path> normalize_path(const std::filesystem::path& p) {
    if (p.empty()) {
        return fail(ErrorCode::InvalidArgument, "utility::normalize_path");
    }
    std::error_code ec;
    auto abs = std::filesystem::absolute(p, ec);
    if (ec) {
        return fail(ErrorCode::IoError, "std::filesystem::absolute", static_cast<std::uint32_t>(ec.value()));
    }
    return abs.lexically_normal();
}

Result<std::filesystem::path> resolve_storage_directory(std::string_view app_id,
                                                        PathScope scope,
                                                        const std::filesystem::path& custom_root) {
    if (app_id.empty()) {
        return fail(ErrorCode::InvalidArgument,
                    "utility::resolve_storage_directory",
                    0,
                    "Application ID cannot be empty");
    }
    if (scope == PathScope::Custom) {
        if (custom_root.empty()) {
            return fail(ErrorCode::InvalidArgument,
                        "utility::resolve_storage_directory",
                        0,
                        "Custom scope requires non-empty custom_root");
        }
        return normalize_path(custom_root / std::filesystem::path(app_id));
    }

    const KNOWNFOLDERID& folder_id =
        (scope == PathScope::Machine) ? FOLDERID_ProgramData : FOLDERID_RoamingAppData;
    PWSTR raw_path = nullptr;
    const HRESULT hr = ::SHGetKnownFolderPath(folder_id, KF_FLAG_DEFAULT, nullptr, &raw_path);
    if (FAILED(hr) || raw_path == nullptr) {
        return fail(ErrorCode::IoError,
                    "SHGetKnownFolderPath",
                    static_cast<std::uint32_t>(hr),
                    "Failed to resolve OS folder path");
    }
    std::filesystem::path base(raw_path);
    ::CoTaskMemFree(raw_path);
    return normalize_path(base / std::filesystem::path(app_id));
}

} // namespace utility

namespace hex {

namespace {

[[nodiscard]] constexpr bool decode_nibble(char c, std::uint8_t& out) noexcept {
    if (c >= '0' && c <= '9') {
        out = static_cast<std::uint8_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        out = static_cast<std::uint8_t>(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        out = static_cast<std::uint8_t>(c - 'A' + 10);
        return true;
    }
    return false;
}

} // namespace

std::string encode(std::span<const std::byte> bytes, bool uppercase) {
    static constexpr char kUpper[] = "0123456789ABCDEF";
    static constexpr char kLower[] = "0123456789abcdef";
    const char* alphabet = uppercase ? kUpper : kLower;

    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto v = std::to_integer<std::uint8_t>(bytes[i]);
        out[i * 2 + 0] = alphabet[(v >> 4) & 0x0Fu];
        out[i * 2 + 1] = alphabet[v & 0x0Fu];
    }
    return out;
}

Result<std::vector<std::byte>> decode(std::string_view hex_text, HexDecodeError* out_error) {
    auto report = [&](std::size_t pos, std::string_view reason) {
        if (out_error != nullptr) {
            *out_error = HexDecodeError{.position = pos, .reason = reason};
        }
        return fail(ErrorCode::ParseError,
                    "hex::decode",
                    0,
                    std::format("at position {}: {}", pos, reason));
    };

    try {
        std::vector<std::byte> out;
        const std::size_t n = hex_text.size();
        std::size_t i = 0;
        while (i < n) {
            while (i < n && utility::is_ascii_space(hex_text[i])) {
                ++i;
            }
            if (i == n) {
                break;
            }

            std::uint8_t hi = 0;
            if (!decode_nibble(hex_text[i], hi)) {
                return report(i, "Invalid high hex character");
            }
            if (i + 1 >= n || utility::is_ascii_space(hex_text[i + 1])) {
                return report(i, "Incomplete hex byte pair (odd number of hex digits)");
            }
            std::uint8_t lo = 0;
            if (!decode_nibble(hex_text[i + 1], lo)) {
                return report(i + 1, "Invalid low hex character");
            }
            out.push_back(static_cast<std::byte>((hi << 4) | lo));
            i += 2;
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "hex::decode");
    }
}

Result<std::uint64_t> parse_u64(std::string_view text) {
    text = utility::trim(text);
    if (text.empty()) {
        return fail(ErrorCode::ParseError, "hex::parse_u64", 0, "Empty hex string");
    }
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
    }
    if (text.empty() || text.size() > 16) {
        return fail(ErrorCode::ParseError, "hex::parse_u64", 0, "Invalid hex integer length");
    }

    std::uint64_t value = 0;
    for (const char c : text) {
        std::uint8_t nib = 0;
        if (!decode_nibble(c, nib)) {
            return fail(ErrorCode::ParseError, "hex::parse_u64", 0, "Invalid hex digit");
        }
        value = (value << 4) | nib;
    }
    return value;
}

std::string format_u64(std::uint64_t value, std::size_t min_digits, bool include_prefix) {
    if (include_prefix) {
        return std::format("0x{:0{}X}", value, min_digits);
    }
    return std::format("{:0{}X}", value, min_digits);
}

} // namespace hex

namespace encoding {

namespace {

[[nodiscard]] constexpr bool decode_next_utf8(std::string_view s,
                                              std::size_t& i,
                                              char32_t& out_cp) noexcept {
    if (i >= s.size()) {
        return false;
    }
    const auto b0 = static_cast<std::uint8_t>(s[i]);
    if (b0 < 0x80u) {
        out_cp = b0;
        ++i;
        return true;
    }
    std::size_t len = 0;
    char32_t cp = 0;
    char32_t min_cp = 0;
    if ((b0 & 0xE0u) == 0xC0u) {
        len = 2;
        cp = b0 & 0x1Fu;
        min_cp = 0x80u;
    } else if ((b0 & 0xF0u) == 0xE0u) {
        len = 3;
        cp = b0 & 0x0Fu;
        min_cp = 0x800u;
    } else if ((b0 & 0xF8u) == 0xF0u) {
        len = 4;
        cp = b0 & 0x07u;
        min_cp = 0x10000u;
    } else {
        return false;
    }

    if (i + len > s.size()) {
        return false;
    }
    for (std::size_t k = 1; k < len; ++k) {
        const auto bx = static_cast<std::uint8_t>(s[i + k]);
        if ((bx & 0xC0u) != 0x80u) {
            return false;
        }
        cp = (cp << 6) | (bx & 0x3Fu);
    }
    if (cp < min_cp || cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
        return false;
    }
    i += len;
    out_cp = cp;
    return true;
}

[[nodiscard]] constexpr bool decode_next_utf16(std::u16string_view s,
                                               std::size_t& i,
                                               char32_t& out_cp) noexcept {
    if (i >= s.size()) {
        return false;
    }
    const auto w1 = static_cast<std::uint16_t>(s[i]);
    if (w1 < 0xD800u || w1 > 0xDFFFu) {
        out_cp = w1;
        ++i;
        return true;
    }
    if (w1 >= 0xDC00u || i + 1 >= s.size()) {
        return false; // Unpaired surrogate
    }
    const auto w2 = static_cast<std::uint16_t>(s[i + 1]);
    if (w2 < 0xDC00u || w2 > 0xDFFFu) {
        return false;
    }
    out_cp = 0x10000u + (((static_cast<char32_t>(w1) - 0xD800u) << 10) |
                         (static_cast<char32_t>(w2) - 0xDC00u));
    i += 2;
    return true;
}

} // namespace

bool is_valid_utf8(std::string_view text) noexcept {
    std::size_t i = 0;
    char32_t cp = 0;
    while (i < text.size()) {
        if (!decode_next_utf8(text, i, cp)) {
            return false;
        }
    }
    return true;
}

bool is_valid_utf16(std::u16string_view text) noexcept {
    std::size_t i = 0;
    char32_t cp = 0;
    while (i < text.size()) {
        if (!decode_next_utf16(text, i, cp)) {
            return false;
        }
    }
    return true;
}

Result<std::u16string> utf8_to_utf16(std::string_view utf8) {
    try {
        std::u16string out;
        out.reserve(utf8.size());
        std::size_t i = 0;
        char32_t cp = 0;
        while (i < utf8.size()) {
            if (!decode_next_utf8(utf8, i, cp)) {
                return fail(ErrorCode::ParseError,
                            "encoding::utf8_to_utf16",
                            0,
                            "Invalid UTF-8 byte sequence");
            }
            if (cp <= 0xFFFFu) {
                out.push_back(static_cast<char16_t>(cp));
            } else {
                const char32_t v = cp - 0x10000u;
                out.push_back(static_cast<char16_t>(0xD800u + (v >> 10)));
                out.push_back(static_cast<char16_t>(0xDC00u + (v & 0x3FFu)));
            }
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "encoding::utf8_to_utf16");
    }
}

Result<std::string> utf16_to_utf8(std::u16string_view utf16) {
    try {
        std::string out;
        out.reserve(utf16.size());
        std::size_t i = 0;
        char32_t cp = 0;
        while (i < utf16.size()) {
            if (!decode_next_utf16(utf16, i, cp)) {
                return fail(ErrorCode::ParseError,
                            "encoding::utf16_to_utf8",
                            0,
                            "Invalid UTF-16 surrogate sequence");
            }
            if (cp < 0x80u) {
                out.push_back(static_cast<char>(cp));
            } else if (cp < 0x800u) {
                out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            } else if (cp < 0x10000u) {
                out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            } else {
                out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
            }
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "encoding::utf16_to_utf8");
    }
}

} // namespace encoding

} // namespace tessera
