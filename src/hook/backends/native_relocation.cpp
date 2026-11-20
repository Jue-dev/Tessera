#include "native_relocation.hpp"

#include <cstring>
#include <limits>

#if defined(_M_X64) || defined(__x86_64__)
    #define TESSERA_HOOK_X64 1
#elif defined(_M_IX86) || defined(__i386__)
    #define TESSERA_HOOK_X86 1
#else
    #error "Tessera native inline hooks support only x86 and x64."
#endif

#include "native_trampoline.hpp"

namespace tessera::detail::native_hook {

[[nodiscard]] bool remap_internal_destination(std::int64_t original_begin,
                                                     const DecodedBlock& block,
                                                     std::uintptr_t trampoline_address,
                                                     std::int64_t& destination) noexcept {
    const std::int64_t original_end =
        original_begin + static_cast<std::int64_t>(block.length);
    if (destination < original_begin || destination >= original_end) {
        return true;
    }

    const auto target_offset = static_cast<std::size_t>(destination - original_begin);
    for (std::size_t i = 0; i < block.instruction_count; ++i) {
        const DecodedInstruction& candidate = block.instructions[i];
        if (candidate.offset == target_offset) {
            destination = static_cast<std::int64_t>(
                trampoline_address + candidate.trampoline_offset);
            return true;
        }
    }

    // A branch into the middle of an instruction cannot be mapped after
    // relocation has changed instruction offsets.
    return false;
}


[[nodiscard]] Status relocate_instructions(const std::byte* original_code,
                                           std::uintptr_t original_address,
                                           std::byte* trampoline,
                                           std::uintptr_t trampoline_address,
                                           const DecodedBlock& block) noexcept {
    const std::int64_t original_begin = static_cast<std::int64_t>(original_address);

    for (std::size_t i = 0; i < block.instruction_count; ++i) {
        const DecodedInstruction& instruction = block.instructions[i];
        const std::byte* original = original_code + instruction.offset;
        std::byte* relocated = trampoline + instruction.trampoline_offset;
        const std::uintptr_t new_ip =
            trampoline_address + instruction.trampoline_offset;

        if (instruction.relocated_length != instruction.length) {
            std::int64_t destination = instruction.relative_target;
            if (!remap_internal_destination(
                    original_begin, block, trampoline_address, destination)) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::relocate",
                            0,
                            "A short branch targets the middle of a relocated instruction");
            }

            if (instruction.opcode == 0xEB) {
                relocated[0] = std::byte{0xE9};
                if (!write_relative32(relocated + 1,
                                      new_ip + instruction.relocated_length,
                                      destination)) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::relocate",
                                0,
                                "The expanded short JMP target is outside rel32 reach");
                }
            } else if (instruction.opcode >= 0x70 && instruction.opcode <= 0x7F) {
                relocated[0] = std::byte{0x0F};
                relocated[1] = static_cast<std::byte>(
                    0x80u | (instruction.opcode & 0x0Fu));
                if (!write_relative32(relocated + 2,
                                      new_ip + instruction.relocated_length,
                                      destination)) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::relocate",
                                0,
                                "The expanded conditional branch target is outside rel32 reach");
                }
            } else {
                // Preserve LOOP-family semantics and its flags by retaining the
                // original short branch. A taken branch skips the fall-through
                // jump and executes the target jump; an untaken branch executes
                // the fall-through jump to the next relocated instruction.
                std::memcpy(relocated, original, instruction.length);
                if (instruction.relative_size != 1 ||
                    instruction.relative_offset >= instruction.length) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::relocate",
                                0,
                                "The short counter branch has an invalid displacement");
                }
                relocated[instruction.relative_offset] = std::byte{0x05};

                std::byte* const fallthrough_jump = relocated + instruction.length;
                const std::uintptr_t fallthrough_jump_ip = new_ip + instruction.length;
                const std::uintptr_t next_relocated_ip = new_ip + instruction.relocated_length;
                if (!write_relative_jump(fallthrough_jump,
                                         fallthrough_jump_ip,
                                         next_relocated_ip)) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::relocate",
                                0,
                                "The LOOP-family fall-through stub is outside rel32 reach");
                }

                std::byte* const target_jump = fallthrough_jump + 5;
                if (!write_relative_jump(target_jump,
                                         fallthrough_jump_ip + 5,
                                         static_cast<std::uintptr_t>(destination))) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::relocate",
                                0,
                                "The LOOP-family target is outside rel32 reach");
                }
            }
            continue;
        }

        std::memcpy(relocated, original, instruction.length);

        if (instruction.has_rip_relative_operand) {
#if defined(TESSERA_HOOK_X64)
            const std::int64_t original_end =
                original_begin + static_cast<std::int64_t>(block.length);
            if (instruction.rip_target >= original_begin &&
                instruction.rip_target < original_end) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::relocate",
                            0,
                            "A RIP-relative memory operand points into the overwritten prologue");
            }

            const std::int64_t new_displacement =
                instruction.rip_target -
                static_cast<std::int64_t>(new_ip + instruction.length);
            if (new_displacement < (std::numeric_limits<std::int32_t>::min)() ||
                new_displacement > (std::numeric_limits<std::int32_t>::max)()) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::relocate",
                            0,
                            "A RIP-relative memory operand is outside the trampoline's reach");
            }
            const auto value = static_cast<std::int32_t>(new_displacement);
            std::memcpy(relocated + instruction.rip_displacement_offset,
                        &value,
                        sizeof(value));
#endif
        }

        if (instruction.has_relative_operand) {
            std::int64_t destination = instruction.relative_target;
            if (!remap_internal_destination(
                    original_begin, block, trampoline_address, destination)) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::relocate",
                            0,
                            "A relative branch targets the middle of a relocated instruction");
            }

            std::byte* relative_field = relocated + instruction.relative_offset;
            const std::uintptr_t new_next = new_ip + instruction.length;
            if (instruction.relative_size == 4) {
                if (!write_relative32(relative_field, new_next, destination)) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::relocate",
                                0,
                                "A relative branch is outside the trampoline's rel32 reach");
                }
            } else {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::relocate",
                            0,
                            "This relative operand width is not supported by the relocator");
            }
        }
    }
    return ok();
}




} // namespace tessera::detail::native_hook
