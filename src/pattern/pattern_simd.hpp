#pragma once

#include <cstddef>
#include <cstdint>

namespace tessera::pattern::detail {

[[nodiscard]] bool cpu_supports_sse2() noexcept;
[[nodiscard]] bool cpu_supports_avx2() noexcept;

[[nodiscard]] std::uint32_t dual_anchor_mask_sse2(
    const std::byte* data,
    std::size_t offset,
    std::size_t primary,
    std::byte primary_value,
    std::size_t secondary,
    std::byte secondary_value) noexcept;

[[nodiscard]] std::uint32_t dual_anchor_mask_avx2(
    const std::byte* data,
    std::size_t offset,
    std::size_t primary,
    std::byte primary_value,
    std::size_t secondary,
    std::byte secondary_value) noexcept;

} // namespace tessera::pattern::detail
