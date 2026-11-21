#include "pattern_simd.hpp"

#if defined(_MSC_VER)
#include <intrin.h>
#include <windows.h>
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#define TESSERA_PATTERN_X86 1
#else
#define TESSERA_PATTERN_X86 0
#endif

namespace tessera::pattern::detail {

bool cpu_supports_sse2() noexcept {
#if defined(TESSERA_PATTERN_FORCE_SCALAR)
    return false;
#elif defined(__x86_64__) || defined(_M_X64)
    return true;
#elif (defined(__GNUC__) || (defined(__clang__) && !defined(_MSC_VER))) && TESSERA_PATTERN_X86
    __builtin_cpu_init();
    return __builtin_cpu_supports("sse2");
#elif defined(_MSC_VER) && defined(_M_IX86)
    int registers[4]{};
    __cpuid(registers, 1);
    return (registers[3] & (1 << 26)) != 0;
#else
    return false;
#endif
}

bool cpu_supports_avx2() noexcept {
#if defined(TESSERA_PATTERN_FORCE_SCALAR)
    return false;
#elif (defined(__GNUC__) || (defined(__clang__) && !defined(_MSC_VER))) && TESSERA_PATTERN_X86
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE) != FALSE;
#else
    return false;
#endif
}

#if TESSERA_PATTERN_X86
#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("sse2")))
#endif
std::uint32_t
dual_anchor_mask_sse2(const std::byte* data, std::size_t offset, std::size_t primary, std::byte primary_value,
                      std::size_t secondary, std::byte secondary_value) noexcept {
    const auto* primary_ptr = reinterpret_cast<const __m128i*>(data + offset + primary);
    const auto* secondary_ptr = reinterpret_cast<const __m128i*>(data + offset + secondary);
    const __m128i primary_bytes = _mm_loadu_si128(primary_ptr);
    const __m128i secondary_bytes = _mm_loadu_si128(secondary_ptr);
    const __m128i primary_key =
        _mm_set1_epi8(static_cast<char>(std::to_integer<unsigned char>(primary_value)));
    const __m128i secondary_key =
        _mm_set1_epi8(static_cast<char>(std::to_integer<unsigned char>(secondary_value)));
    const __m128i primary_match = _mm_cmpeq_epi8(primary_bytes, primary_key);
    const __m128i secondary_match = _mm_cmpeq_epi8(secondary_bytes, secondary_key);
    return static_cast<std::uint32_t>(_mm_movemask_epi8(_mm_and_si128(primary_match, secondary_match)));
}
#else
std::uint32_t dual_anchor_mask_sse2(const std::byte*, std::size_t, std::size_t, std::byte, std::size_t,
                                    std::byte) noexcept {
    return 0;
}
#endif

} // namespace tessera::pattern::detail
