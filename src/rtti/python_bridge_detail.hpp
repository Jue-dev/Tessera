#pragma once

#include "tessera/rtti/python_bridge.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include "tessera/memory/memory_reader.hpp"
#include "readable_chunks.hpp"

namespace tessera::rtti {
namespace {

using detail::for_each_readable_chunk;



[[maybe_unused, nodiscard]] bool is_python_identifier(std::string_view s, bool allow_dots = false) noexcept {
    if (s.size() < 2 || s.size() > 96) {
        return false;
    }
    const auto first = static_cast<unsigned char>(s[0]);
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_')) {
        return false;
    }
    for (std::size_t i = 1; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || (allow_dots && c == '.');
        if (!ok) {
            return false;
        }
    }
    return true;
}

[[maybe_unused, nodiscard]] bool is_valid_meth_flags(std::uint32_t flags) noexcept {
    if (flags == 0) {
        return false;
    }
    // Valid CPython METH_* flags bitmask (0x0001..0x0400)
    constexpr std::uint32_t kAllowedMask = 0x07FFu;
    if ((flags & ~kAllowedMask) != 0) {
        return false;
    }
    // Must contain at least one calling convention bit (VARARGS=1, NOARGS=4, O=8, FASTCALL=0x80)
    return (flags & (0x01u | 0x02u | 0x04u | 0x08u | 0x80u)) != 0;
}

[[maybe_unused, nodiscard]] bool is_plausible_python_refcount(std::uint64_t refcnt) noexcept {
    // Ordinary live objects have small positive counts. CPython 3.13 marks
    // immortal objects with UINT_MAX on 64-bit and UINT_MAX >> 2 on 32-bit.
    // Accept those exact encodings (plus the all-ones encoding used by some
    // builds), without opening the heuristic to arbitrary large integers.
    constexpr std::uint64_t kImmortal64 = 0x00000000FFFFFFFFULL;
    constexpr std::uint64_t kImmortal32 = 0x000000003FFFFFFFULL;
    constexpr std::uint64_t kAllOnes = 0xFFFFFFFFFFFFFFFFULL;
    return refcnt != 0 &&
           (refcnt <= 0x10000ULL || refcnt == kImmortal64 ||
            refcnt == kImmortal32 || refcnt == kAllOnes);
}

[[maybe_unused, nodiscard]] std::uint64_t read_ptr_at(std::span<const std::byte> buf,
                                        std::size_t off,
                                        std::uint8_t ptr_size) noexcept {
    if (ptr_size == 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, buf.data() + off, 8);
        return v;
    }
    std::uint32_t v = 0;
    std::memcpy(&v, buf.data() + off, 4);
    return v;
}


} // namespace
} // namespace tessera::rtti
