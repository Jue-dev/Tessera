#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "tessera/core/result.hpp"

namespace tessera::detail::native_hook {

struct DecodedInstruction {
    std::size_t offset = 0;
    std::size_t length = 0;
    std::size_t trampoline_offset = 0;
    std::size_t relocated_length = 0;
    std::size_t relative_offset = 0;
    std::size_t relative_size = 0;
    std::int64_t relative_target = 0;
    std::size_t rip_displacement_offset = 0;
    std::int64_t rip_target = 0;
    std::uint8_t opcode = 0;
    std::uint8_t opcode2 = 0;
    std::uint8_t modrm_reg = 0;
    bool has_relative_operand = false;
    bool has_rip_relative_operand = false;
};

struct DecodedBlock {
    std::array<DecodedInstruction, 16> instructions{};
    std::size_t instruction_count = 0;
    std::size_t length = 0;
    std::size_t trampoline_length = 0;
    std::size_t entry_prefix_size = 0;
};


inline constexpr std::size_t kMaximumPatchBytes = 32;

[[nodiscard]] bool remap_internal_destination(std::int64_t original_begin,
                                              const DecodedBlock& block,
                                              std::uintptr_t trampoline_address,
                                              std::int64_t& destination) noexcept;

[[nodiscard]] Status relocate_instructions(const std::byte* original_code,
                                           std::uintptr_t original_address,
                                           std::byte* trampoline,
                                           std::uintptr_t trampoline_address,
                                           const DecodedBlock& block) noexcept;

} // namespace tessera::detail::native_hook
