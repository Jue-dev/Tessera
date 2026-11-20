#include "native_unwind.hpp"
#if defined(_M_X64) || defined(__x86_64__)
#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
namespace tessera::detail::native_hook {
namespace {
struct NativeUnwindCode { UCHAR CodeOffset=0; UCHAR Operation=0; };
struct NativeUnwindInfoHeader { UCHAR VersionAndFlags=0; UCHAR SizeOfProlog=0; UCHAR CountOfCodes=0; UCHAR FrameRegisterAndOffset=0; };
static_assert(sizeof(NativeUnwindInfoHeader)==4u);
static_assert(sizeof(NativeUnwindCode)==2u);
constexpr unsigned int kUnwindOpPushNonVol=0u;
constexpr unsigned int kUnwindOpAllocLarge=1u;
constexpr unsigned int kUnwindOpAllocSmall=2u;
constexpr unsigned int kUnwindOpSetFpReg=3u;
constexpr unsigned int kUnwindOpSaveNonVol=4u;
constexpr unsigned int kUnwindOpSaveNonVolFar=5u;
constexpr unsigned int kUnwindOpSaveXmm128=8u;
constexpr unsigned int kUnwindOpSaveXmm128Far=9u;
constexpr unsigned int kUnwindOpPushMachFrame=10u;

[[nodiscard]] constexpr bool is_nonvolatile_gpr(unsigned int reg) noexcept {
    return reg == 3u || reg == 5u || reg == 6u || reg == 7u ||
           (reg >= 12u && reg <= 15u);
}

[[nodiscard]] constexpr bool is_volatile_gpr(unsigned int reg) noexcept {
    return reg == 0u || reg == 1u || reg == 2u ||
           (reg >= 8u && reg <= 11u);
}

// A target without a registered RUNTIME_FUNCTION is only accepted as a leaf
// when every stolen instruction is in this deliberately small, auditable
// stack-neutral subset. Unknown encodings fail closed instead of receiving
// synthetic leaf unwind semantics.
[[nodiscard]] bool is_leaf_safe_instruction(
    const std::byte* code,
    const DecodedInstruction& instruction) noexcept {
    // Explicit vector-instruction allowlist: VZEROUPPER and the VADDPS
    // ZMM0,ZMM0,ZMM0 form touch only volatile vector state.
    if (instruction.length == 3u &&
        code[0] == std::byte{0xC5} &&
        code[1] == std::byte{0xF8} &&
        code[2] == std::byte{0x77}) {
        return true;
    }
    if (instruction.length == 6u &&
        code[0] == std::byte{0x62} &&
        code[1] == std::byte{0xF1} &&
        code[2] == std::byte{0x7C} &&
        code[3] == std::byte{0x48} &&
        code[4] == std::byte{0x58} &&
        code[5] == std::byte{0xC0}) {
        return true;
    }

    std::size_t cursor = 0;
    std::uint8_t rex = 0;
    while (cursor < instruction.length) {
        const auto value = std::to_integer<std::uint8_t>(code[cursor]);
        if (value >= 0x40u && value <= 0x4Fu) {
            rex = value;
            ++cursor;
            continue;
        }
        if (value == 0x66u || value == 0x67u ||
            value == 0x2Eu || value == 0x36u ||
            value == 0x3Eu || value == 0x26u ||
            value == 0x64u || value == 0x65u) {
            rex = 0u; // A later legacy prefix makes an earlier REX ineffective.
            ++cursor;
            continue;
        }
        if (value == 0xF0u || value == 0xF2u || value == 0xF3u) {
            return false;
        }
        break;
    }
    if (cursor >= instruction.length) {
        return false;
    }

    const auto opcode = std::to_integer<std::uint8_t>(code[cursor++]);
    if (opcode == 0x90u || opcode == 0xCCu || opcode == 0xC3u) {
        return true;
    }
    if (opcode == 0x0Fu) {
        if (cursor >= instruction.length) {
            return false;
        }
        const auto opcode2 = std::to_integer<std::uint8_t>(code[cursor++]);
        if (opcode2 == 0x1Fu) {
            return true; // Multi-byte NOP.
        }
        if (opcode2 == 0x0Bu) {
            return true; // UD2 traps without changing the stack or nonvolatile state.
        }
        if (opcode2 >= 0x80u && opcode2 <= 0x8Fu) {
            return true; // Near conditional branch.
        }
        return false;
    }
    if (opcode == 0xE8u) {
        // A direct relative CALL is balanced when its callee returns. CALL $+5
        // is rejected by decode_block using the original instruction address.
        return instruction.has_relative_operand;
    }
    if ((opcode >= 0x70u && opcode <= 0x7Fu) ||
        (opcode >= 0xE0u && opcode <= 0xE3u) ||
        opcode == 0xE9u || opcode == 0xEBu) {
        return true;
    }
    if (opcode >= 0xB8u && opcode <= 0xBFu) {
        const unsigned int reg =
            static_cast<unsigned int>(opcode - 0xB8u) + ((rex & 0x01u) != 0u ? 8u : 0u);
        return is_volatile_gpr(reg);
    }
    if (opcode == 0x80u || opcode == 0x81u || opcode == 0x83u) {
        if (cursor >= instruction.length) {
            return false;
        }
        const auto modrm = std::to_integer<std::uint8_t>(code[cursor]);
        const unsigned int mod = (modrm >> 6u) & 0x03u;
        const unsigned int rm_field =
            (modrm & 0x07u) + ((rex & 0x01u) != 0u ? 8u : 0u);
        // Group-1 immediate arithmetic is leaf-compatible only when it writes
        // a volatile register, never RSP/RBP or a nonvolatile register.
        return mod == 0x03u && is_volatile_gpr(rm_field);
    }
    if (opcode <= 0x3Fu) {
        const unsigned int form = opcode & 0x07u;
        if (form == 0u || form == 1u || form == 2u || form == 3u) {
            if (opcode >= 0x38u) {
                return true; // CMP never writes its operand.
            }
            if (cursor >= instruction.length) {
                return false;
            }
            const auto modrm = std::to_integer<std::uint8_t>(code[cursor]);
            const unsigned int mod = (modrm >> 6u) & 0x03u;
            const unsigned int reg_field =
                ((modrm >> 3u) & 0x07u) + ((rex & 0x04u) != 0u ? 8u : 0u);
            const unsigned int rm_field =
                (modrm & 0x07u) + ((rex & 0x01u) != 0u ? 8u : 0u);
            if ((form & 0x02u) != 0u) {
                return is_volatile_gpr(reg_field);
            }
            return mod == 0x03u && is_volatile_gpr(rm_field);
        }
        if (form == 4u || form == 5u) {
            return true; // Accumulator-immediate arithmetic only writes RAX/EAX.
        }
    }

    // Only register-destination forms are accepted below. Memory writes,
    // stack operations, calls, and writes to nonvolatile registers are not
    // leaf-compatible.
    if (cursor >= instruction.length) {
        return false;
    }
    const auto modrm = std::to_integer<std::uint8_t>(code[cursor]);
    const unsigned int mod = (modrm >> 6u) & 0x03u;
    const unsigned int reg_field =
        ((modrm >> 3u) & 0x07u) + ((rex & 0x04u) != 0u ? 8u : 0u);
    const unsigned int rm_field =
        (modrm & 0x07u) + ((rex & 0x01u) != 0u ? 8u : 0u);

    if (opcode == 0x8Du || opcode == 0x8Bu) {
        return is_volatile_gpr(reg_field); // LEA / MOV destination is ModRM.reg.
    }
    if (opcode == 0x89u) {
        return mod == 0x03u && is_volatile_gpr(rm_field);
    }
    if (opcode == 0x85u || opcode == 0x84u) {
        return true; // TEST does not write a general-purpose register.
    }
    if (opcode == 0xFFu && (instruction.modrm_reg == 4u || instruction.modrm_reg == 5u)) {
        return true; // Indirect tail jump, not CALL.
    }
    return false;
}

[[nodiscard]] bool is_leaf_safe_block(
    const std::byte* original_code,
    const DecodedBlock& block) noexcept {
    for (std::size_t index = 0; index < block.instruction_count; ++index) {
        const auto& instruction = block.instructions[index];
        if (!is_leaf_safe_instruction(original_code + instruction.offset, instruction)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool map_unwind_code_offset(
    std::uint8_t source_offset,
    std::size_t entry_prefix_size,
    std::size_t trampoline_entry_prefix_size,
    const DecodedBlock& block,
    std::uint8_t& trampoline_offset) noexcept {
    // The preserved source prefix is only an ENDBR landing pad. It cannot
    // complete a stack-unwind operation, so CodeOffset must be strictly after it.
    if (source_offset <= entry_prefix_size) {
        return false;
    }
    const std::size_t patch_offset =
        static_cast<std::size_t>(source_offset) - entry_prefix_size;
    if (patch_offset == 0u || patch_offset > block.length) {
        return false;
    }
    for (std::size_t index = 0; index < block.instruction_count; ++index) {
        const auto& instruction = block.instructions[index];
        if (instruction.offset + instruction.length == patch_offset) {
            const std::size_t mapped =
                trampoline_entry_prefix_size + instruction.trampoline_offset +
                instruction.relocated_length;
            if (mapped > (std::numeric_limits<std::uint8_t>::max)()) {
                return false;
            }
            trampoline_offset = static_cast<std::uint8_t>(mapped);
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool unwind_slot_count(
    const NativeUnwindCode& code,
    std::size_t& slot_count) noexcept {
    const unsigned int op = code.Operation & 0x0Fu;
    const unsigned int info = code.Operation >> 4u;
    switch (op) {
        case kUnwindOpPushNonVol:
            if (!is_nonvolatile_gpr(info)) return false;
            slot_count = 1u;
            return true;
        case kUnwindOpAllocLarge:
            if (info == 0u) slot_count = 2u;
            else if (info == 1u) slot_count = 3u;
            else return false;
            return true;
        case kUnwindOpAllocSmall:
            slot_count = 1u;
            return true;
        case kUnwindOpSetFpReg:
            if (info != 0u) return false;
            slot_count = 1u;
            return true;
        case kUnwindOpSaveNonVol:
            if (!is_nonvolatile_gpr(info)) return false;
            slot_count = 2u;
            return true;
        case kUnwindOpSaveNonVolFar:
            if (!is_nonvolatile_gpr(info)) return false;
            slot_count = 3u;
            return true;
        case kUnwindOpSaveXmm128:
            if (info < 6u || info > 15u) return false;
            slot_count = 2u;
            return true;
        case kUnwindOpSaveXmm128Far:
            if (info < 6u || info > 15u) return false;
            slot_count = 3u;
            return true;
        case kUnwindOpPushMachFrame:
            if (info > 1u) return false;
            slot_count = 1u;
            return true;
        default:
            // Version-2 epilog/spare operations and unknown encodings are not
            // copied until their semantics can be represented exactly.
            return false;
    }
}

[[nodiscard]] bool is_readable_memory_range(
    const void* address,
    std::size_t size) noexcept {
    if (address == nullptr || size == 0u) {
        return false;
    }

    constexpr std::uintptr_t kMaximumAddress =
        (std::numeric_limits<std::uintptr_t>::max)();
    const std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(address);
    if (size > kMaximumAddress - begin) {
        return false;
    }
    const std::uintptr_t end = begin + static_cast<std::uintptr_t>(size);

    std::uintptr_t cursor = begin;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION region{};
        if (::VirtualQuery(reinterpret_cast<const void*>(cursor),
                           &region,
                           sizeof(region)) != sizeof(region) ||
            region.State != MEM_COMMIT ||
            (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u) {
            return false;
        }

        switch (region.Protect & 0xFFu) {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                break;
            default:
                return false;
        }

        const std::uintptr_t region_begin =
            reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        if (region.RegionSize > kMaximumAddress - region_begin) {
            return false;
        }
        const std::uintptr_t region_end =
            region_begin + static_cast<std::uintptr_t>(region.RegionSize);
        if (region_end <= cursor) {
            return false;
        }
        cursor = (std::min)(end, region_end);
    }
    return true;
}


} // namespace
[[nodiscard]] Status prepare_trampoline_unwind(
    void* allocation_base, void* target, const std::byte* original_code,
    std::size_t entry_prefix_size, const DecodedBlock& block,
    std::size_t trampoline_entry_prefix_size, std::size_t return_jump_size,
    std::size_t unwind_info_offset, RUNTIME_FUNCTION& unwind_function) noexcept {
    auto* const allocation = static_cast<std::byte*>(allocation_base);
    std::byte* const unwind_info_bytes =
        allocation + unwind_info_offset;
    std::memset(unwind_info_bytes, 0, kMaximumUnwindInfoBytes);
    NativeUnwindInfoHeader unwind_info{};

    DWORD64 image_base = 0;
    const DWORD64 target_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(target));
    PRUNTIME_FUNCTION source_function =
        ::RtlLookupFunctionEntry(target_address, &image_base, nullptr);

    if (source_function == nullptr) {
        if (!is_leaf_safe_block(original_code, block)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "No source unwind record exists and the stolen instructions are not provably leaf-safe");
        }
        unwind_info.VersionAndFlags = 1u;
        unwind_info.SizeOfProlog = 0u;
        unwind_info.CountOfCodes = 0u;
        unwind_info.FrameRegisterAndOffset = 0u;
    } else {
        if (!is_readable_memory_range(source_function, sizeof(*source_function))) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "The source runtime-function record is not fully readable");
        }
        if (image_base > (std::numeric_limits<DWORD64>::max)() - source_function->BeginAddress ||
            image_base > (std::numeric_limits<DWORD64>::max)() - source_function->EndAddress ||
            image_base > (std::numeric_limits<DWORD64>::max)() - source_function->UnwindData) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "The source runtime-function record overflows its image base");
        }
        const DWORD64 source_begin = image_base + source_function->BeginAddress;
        const DWORD64 source_end = image_base + source_function->EndAddress;
        if (target_address != source_begin || source_end <= source_begin ||
            source_function->UnwindData == 0u) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "Only hooks at the beginning of a registered function are supported");
        }

        const DWORD64 source_function_size = source_end - source_begin;
        const DWORD64 source_unwind_address = image_base + source_function->UnwindData;
        if ((source_unwind_address & 0x03u) != 0u ||
            !is_readable_memory_range(
                reinterpret_cast<const void*>(static_cast<std::uintptr_t>(source_unwind_address)),
                sizeof(NativeUnwindInfoHeader))) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "The source unwind-info header is unaligned or not fully readable");
        }

        const auto* const source_info_bytes =
            reinterpret_cast<const std::byte*>(
                static_cast<std::uintptr_t>(source_unwind_address));
        NativeUnwindInfoHeader source_info{};
        std::memcpy(&source_info, source_info_bytes, sizeof(source_info));
        const std::size_t source_unwind_size =
            sizeof(NativeUnwindInfoHeader) +
            static_cast<std::size_t>(source_info.CountOfCodes) * sizeof(NativeUnwindCode);
        if (!is_readable_memory_range(source_info_bytes, source_unwind_size)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "The source unwind-code array extends outside readable committed memory");
        }
        const std::byte* const source_code_bytes =
            source_info_bytes + sizeof(NativeUnwindInfoHeader);

        if ((source_info.VersionAndFlags & 0x07u) != 1u ||
            (source_info.VersionAndFlags >> 3u) != 0u) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "Only version-1 unwind records without handlers or chained records are supported");
        }

        const std::size_t source_patch_end = entry_prefix_size + block.length;
        if (source_patch_end > source_function_size ||
            source_info.SizeOfProlog > source_function_size) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "The stolen prologue extends beyond the registered source function");
        }

        std::size_t input_slot = 0u;
        std::size_t output_slot = 0u;
        std::uint8_t previous_code_offset = (std::numeric_limits<std::uint8_t>::max)();
        bool source_frame_setup = false;
        bool copied_frame_setup = false;
        while (input_slot < source_info.CountOfCodes) {
            NativeUnwindCode source_code{};
            std::memcpy(&source_code,
                        source_code_bytes + input_slot * sizeof(NativeUnwindCode),
                        sizeof(source_code));
            std::size_t slots = 0u;
            if (source_code.CodeOffset == 0u ||
                !unwind_slot_count(source_code, slots) ||
                slots > static_cast<std::size_t>(source_info.CountOfCodes) - input_slot ||
                source_code.CodeOffset > previous_code_offset ||
                source_code.CodeOffset > source_info.SizeOfProlog) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::unwind",
                            0,
                            "The source unwind-code stream is malformed or uses an unsupported opcode");
            }
            previous_code_offset = source_code.CodeOffset;
            source_frame_setup |= (source_code.Operation & 0x0Fu) == kUnwindOpSetFpReg;

            if (source_code.CodeOffset <= source_patch_end) {
                std::uint8_t mapped_offset = 0u;
                if (!map_unwind_code_offset(source_code.CodeOffset,
                                            entry_prefix_size,
                                            trampoline_entry_prefix_size,
                                            block,
                                            mapped_offset) ||
                    output_slot + slots > 255u) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::unwind",
                                0,
                                "A source unwind operation does not map to a relocated instruction boundary");
                }

                std::byte* const destination_code =
                    unwind_info_bytes + sizeof(NativeUnwindInfoHeader) +
                    output_slot * sizeof(NativeUnwindCode);
                const std::byte* const source_code_slots =
                    source_code_bytes + input_slot * sizeof(NativeUnwindCode);
                std::memcpy(destination_code,
                            source_code_slots,
                            slots * sizeof(NativeUnwindCode));
                NativeUnwindCode mapped_code = source_code;
                mapped_code.CodeOffset = mapped_offset;
                std::memcpy(destination_code, &mapped_code, sizeof(mapped_code));
                if ((source_code.Operation & 0x0Fu) == kUnwindOpSetFpReg) {
                    copied_frame_setup = true;
                }
                output_slot += slots;
            }
            input_slot += slots;
        }

        std::uint8_t mapped_prolog_size = 0u;
        if (source_info.SizeOfProlog <= entry_prefix_size) {
            mapped_prolog_size = source_info.SizeOfProlog;
        } else if (source_info.SizeOfProlog <= source_patch_end) {
            if (!map_unwind_code_offset(source_info.SizeOfProlog,
                                        entry_prefix_size,
                                        trampoline_entry_prefix_size,
                                        block,
                                        mapped_prolog_size)) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::unwind",
                            0,
                            "The end of the source prologue does not map to a relocated instruction boundary");
            }
        } else {
            const std::size_t relocated_end =
                trampoline_entry_prefix_size + block.trampoline_length;
            if (relocated_end > (std::numeric_limits<std::uint8_t>::max)()) {
                return fail(ErrorCode::UnsupportedInstruction, "NativeInlineHook::unwind");
            }
            mapped_prolog_size = static_cast<std::uint8_t>(relocated_end);
        }

        const unsigned int source_frame_register =
            source_info.FrameRegisterAndOffset & 0x0Fu;
        const unsigned int source_frame_offset =
            source_info.FrameRegisterAndOffset >> 4u;
        if (((source_frame_register != 0u) != source_frame_setup) ||
            (source_frame_register == 0u && source_frame_offset != 0u)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "The source frame-register header and SET_FPREG operation disagree");
        }
        if (copied_frame_setup) {
            if (!is_nonvolatile_gpr(source_frame_register)) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::unwind",
                            0,
                            "The source frame-register description is invalid");
            }
            unwind_info.FrameRegisterAndOffset = source_info.FrameRegisterAndOffset;
        }

        unwind_info.VersionAndFlags = 1u;
        unwind_info.SizeOfProlog = mapped_prolog_size;
        unwind_info.CountOfCodes = static_cast<UCHAR>(output_slot);
    }

    std::memcpy(unwind_info_bytes, &unwind_info, sizeof(unwind_info));

    unwind_function.BeginAddress = 0u;
    unwind_function.EndAddress = static_cast<DWORD>(
        trampoline_entry_prefix_size + block.trampoline_length + return_jump_size);
    unwind_function.UnwindData = static_cast<DWORD>(unwind_info_offset);
    return ok();
}


[[nodiscard]] Status register_trampoline_unwind(
    RUNTIME_FUNCTION& unwind_function, bool& unwind_registered,
    void* allocation_base) noexcept {
    // The UNWIND_INFO bytes must already be finalized while the trampoline
    // allocation is writable. This function only publishes the read-only data.
    if (!::RtlAddFunctionTable(
            &unwind_function,
            1u,
            static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(allocation_base)))) {
        // The BOOLEAN API does not document a last-error contract.
        return fail(ErrorCode::IoError,
                    "RtlAddFunctionTable",
                    0,
                    "Windows rejected the generated trampoline runtime-function record");
    }
    unwind_registered = true;
    return ok();
}


[[nodiscard]] bool unregister_trampoline_unwind(
    RUNTIME_FUNCTION& unwind_function, bool& unwind_registered) noexcept {
    if (!unwind_registered) return true;
    if (!::RtlDeleteFunctionTable(&unwind_function)) return false;
    unwind_registered = false;
    return true;
}
} // namespace tessera::detail::native_hook
#endif // x64
