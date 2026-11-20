#pragma once

// Tessera's private x86/x64 instruction-length decoder.
//
// This decoder is intentionally scoped to native-hook prologue analysis. It
// reports instruction boundaries and the relative operands that the
// relocator must repair; it is not a public disassembler API. Every read is
// bounded by both the caller-supplied span and the architectural 15-byte
// instruction limit. Encodings outside the supported maps are rejected.

#include <cstddef>
#include <cstdint>

namespace tessera::detail::x86 {

enum class Mode : std::uint8_t {
    x86,
    x64,
};

struct DecodedInstruction {
    std::uint8_t length = 0;
    std::uint8_t opcode = 0;
    std::uint8_t opcode2 = 0;
    std::uint8_t modrm_reg = 0;
    std::uint8_t relative_offset = 0;
    std::uint8_t relative_size = 0;
    std::uint8_t rip_displacement_offset = 0;
    bool has_relative_operand = false;
    bool has_rip_relative_operand = false;
};

[[nodiscard]] bool decode_instruction(
    const std::byte* code,
    std::size_t available,
    Mode mode,
    DecodedInstruction& output) noexcept;

} // namespace tessera::detail::x86
