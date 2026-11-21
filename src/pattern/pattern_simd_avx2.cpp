#include "pattern_simd.hpp"

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#define TESSERA_PATTERN_X86 1
#else
#define TESSERA_PATTERN_X86 0
#endif

namespace tessera::pattern::detail {

#if TESSERA_PATTERN_X86
#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
#endif
std::uint32_t dual_anchor_mask_avx2(
    const std::byte* data,
    std::size_t offset,
    std::size_t primary,
    std::byte primary_value,
    std::size_t secondary,
    std::byte secondary_value) noexcept {
    const auto* primary_ptr = reinterpret_cast<const __m256i*>(data + offset + primary);
    const auto* secondary_ptr = reinterpret_cast<const __m256i*>(data + offset + secondary);
    const __m256i primary_bytes = _mm256_loadu_si256(primary_ptr);
    const __m256i secondary_bytes = _mm256_loadu_si256(secondary_ptr);
    const __m256i primary_key = _mm256_set1_epi8(static_cast<char>(std::to_integer<unsigned char>(primary_value)));
    const __m256i secondary_key = _mm256_set1_epi8(static_cast<char>(std::to_integer<unsigned char>(secondary_value)));
    const __m256i primary_match = _mm256_cmpeq_epi8(primary_bytes, primary_key);
    const __m256i secondary_match = _mm256_cmpeq_epi8(secondary_bytes, secondary_key);
    return static_cast<std::uint32_t>(
        _mm256_movemask_epi8(_mm256_and_si256(primary_match, secondary_match)));
}
#else
std::uint32_t dual_anchor_mask_avx2(
    const std::byte*, std::size_t, std::size_t, std::byte, std::size_t, std::byte) noexcept {
    return 0;
}
#endif

} // namespace tessera::pattern::detail
