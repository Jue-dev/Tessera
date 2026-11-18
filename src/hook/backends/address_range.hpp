#pragma once

#include <cstddef>
#include <cstdint>

namespace tessera::detail {

// Overflow-safe half-open address-range overlap test. The implementation uses
// subtraction instead of end-address addition so ranges near UINTPTR_MAX do
// not wrap and become invisible to conflict detection.
[[nodiscard]] constexpr bool address_ranges_overlap(
    std::uintptr_t lhs_begin,
    std::size_t lhs_size,
    std::uintptr_t rhs_begin,
    std::size_t rhs_size) noexcept {
    if (lhs_size == 0 || rhs_size == 0) {
        return false;
    }
    if (lhs_begin <= rhs_begin) {
        return rhs_begin - lhs_begin < lhs_size;
    }
    return lhs_begin - rhs_begin < rhs_size;
}

// Overflow-safe membership test for a half-open address range.
[[nodiscard]] constexpr bool address_range_contains(
    std::uintptr_t range_begin,
    std::size_t range_size,
    std::uintptr_t address) noexcept {
    return range_size != 0 && address >= range_begin &&
           address - range_begin < range_size;
}

} // namespace tessera::detail
