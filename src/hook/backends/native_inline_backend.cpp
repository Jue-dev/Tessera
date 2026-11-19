#include "tessera/hook/hook.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <utility>
#include <vector>

#include "platform/windows/thread_backend.hpp"
#include "patch_write_transaction.hpp"
#include "address_range.hpp"

#if defined(_M_X64) || defined(__x86_64__)
    #define TESSERA_HOOK_X64 1
#elif defined(_M_IX86) || defined(__i386__)
    #define TESSERA_HOOK_X86 1
#else
    #error "Tessera native inline hooks support only x86 and x64."
#endif
#include "x86_instruction_decoder.hpp"

namespace tessera {
namespace {

#if defined(TESSERA_HOOK_X64)
constexpr detail::x86::Mode kNativeDecoderMode = detail::x86::Mode::x64;
#else
constexpr detail::x86::Mode kNativeDecoderMode = detail::x86::Mode::x86;
#endif

constexpr std::size_t kMaximumPatchBytes = 32;
constexpr std::size_t kMaximumReadBytes = 96;
constexpr std::size_t kTrampolineCodeCapacity = 256;
constexpr std::size_t kTrampolineRelayOffset = kTrampolineCodeCapacity;
constexpr std::size_t kAbsoluteJumpSize = 14;
#if defined(TESSERA_HOOK_X64)
// Windows SDKs consistently expose RUNTIME_FUNCTION and the registration
// APIs, but not UNWIND_INFO/UNWIND_CODE in every SDK version. Keep the wire
// format private and byte-oriented so the layout is SDK independent.
struct NativeUnwindCode {
    UCHAR CodeOffset = 0;
    UCHAR Operation = 0; // low nibble: operation; high nibble: operation info.
};

struct NativeUnwindInfo {
    UCHAR VersionAndFlags = 0; // low 3 bits: version; high 5 bits: flags.
    UCHAR SizeOfProlog = 0;
    UCHAR CountOfCodes = 0;
    UCHAR FrameRegisterAndOffset = 0; // low 4 bits: register; high 4 bits: offset.
    NativeUnwindCode UnwindCode[1]{};
};

static_assert(offsetof(NativeUnwindInfo, UnwindCode) == 4u);
static_assert(sizeof(NativeUnwindCode) == 2u);

constexpr unsigned int kUnwindOpPushNonVol = 0u;
constexpr unsigned int kUnwindOpAllocLarge = 1u;
constexpr unsigned int kUnwindOpAllocSmall = 2u;
constexpr unsigned int kUnwindOpSetFpReg = 3u;
constexpr unsigned int kUnwindOpSaveNonVol = 4u;
constexpr unsigned int kUnwindOpSaveNonVolFar = 5u;
constexpr unsigned int kUnwindOpSaveXmm128 = 8u;
constexpr unsigned int kUnwindOpSaveXmm128Far = 9u;
constexpr unsigned int kUnwindOpPushMachFrame = 10u;

constexpr std::size_t kTrampolineUnwindInfoOffset =
    (kTrampolineRelayOffset + kAbsoluteJumpSize + 3u) & ~std::size_t{3u};
constexpr std::size_t kMaximumUnwindInfoBytes =
    (offsetof(NativeUnwindInfo, UnwindCode) +
     255u * sizeof(NativeUnwindCode) + 3u) & ~std::size_t{3u};
constexpr std::size_t kTrampolineAllocationSize =
    kTrampolineUnwindInfoOffset + kMaximumUnwindInfoBytes;
#else
constexpr std::size_t kTrampolineAllocationSize =
    kTrampolineCodeCapacity + kAbsoluteJumpSize;
#endif
constexpr std::size_t kEntryJumpSize = 5;
constexpr std::size_t kReturnJumpSize = 5;
constexpr std::size_t kTrampolineEntryPrefixSize = 4;
#if defined(TESSERA_HOOK_X64)
constexpr std::array<std::byte, kTrampolineEntryPrefixSize> kTrampolineLandingPad{
    std::byte{0xF3}, std::byte{0x0F}, std::byte{0x1E}, std::byte{0xFA}}; // ENDBR64
#else
constexpr std::array<std::byte, kTrampolineEntryPrefixSize> kTrampolineLandingPad{
    std::byte{0xF3}, std::byte{0x0F}, std::byte{0x1E}, std::byte{0xFB}}; // ENDBR32
#endif
static_assert(kTrampolineEntryPrefixSize + (kMaximumPatchBytes / 2) * 12 +
                  kReturnJumpSize <=
              kTrampolineCodeCapacity);

[[nodiscard]] constexpr bool is_valid_thread_policy(ThreadPolicy policy) noexcept {
    return policy == ThreadPolicy::SuspendOthersStrict ||
           policy == ThreadPolicy::SuspendOthersBestEffort ||
           policy == ThreadPolicy::None;
}

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

[[nodiscard]] bool is_padding_instruction(const DecodedInstruction& instruction) noexcept {
    return instruction.opcode == 0x90 || instruction.opcode == 0xCC ||
           (instruction.opcode == 0x0F && instruction.opcode2 == 0x1F);
}

[[nodiscard]] bool is_terminal_instruction(const DecodedInstruction& instruction) noexcept {
    if (instruction.opcode == 0xE9 || instruction.opcode == 0xEB ||
        instruction.opcode == 0xC2 || instruction.opcode == 0xC3 ||
        instruction.opcode == 0xCA || instruction.opcode == 0xCB ||
        instruction.opcode == 0xCF || instruction.opcode == 0xEA) {
        return true;
    }
    return instruction.opcode == 0xFF &&
           (instruction.modrm_reg == 4 || instruction.modrm_reg == 5);
}

struct NativeHookState {
    void* target = nullptr;
    void* patch_target = nullptr;
    void* detour = nullptr;
    void* trampoline = nullptr;
    void* relay = nullptr;
    void* allocation = nullptr;
    std::size_t allocation_size = 0;
    std::size_t patch_size = 0;
    DWORD original_protection = 0;
    std::array<std::byte, 4> entry_prefix_bytes{};
    std::array<std::byte, kMaximumPatchBytes> original_bytes{};
    std::array<std::byte, kMaximumPatchBytes> patch_bytes{};
#if defined(TESSERA_HOOK_X64)
    RUNTIME_FUNCTION unwind_function{};
    bool unwind_registered = false;
    bool target_detached = false;
#endif

    ~NativeHookState() noexcept {
#if defined(TESSERA_HOOK_X64)
        // Never release either the dynamic function-table entry or its code/data
        // while the OS can still consult it during stack walking.
        if (unwind_registered && !::RtlDeleteFunctionTable(&unwind_function)) {
            std::terminate();
        }
#endif
        if (allocation != nullptr) {
            (void)::VirtualFree(allocation, 0, MEM_RELEASE);
        }
    }
};


// The process-wide hook lock serializes every access to this registry. Keeping
// the actual patched ranges (rather than only entry addresses) prevents two
// native hooks from owning overlapping instruction bytes.
[[nodiscard]] std::vector<NativeHookState*>& active_native_hooks() {
    static std::vector<NativeHookState*> hooks{};
    return hooks;
}

[[nodiscard]] bool overlaps(std::uintptr_t lhs_begin,
                             std::size_t lhs_size,
                             std::uintptr_t rhs_begin,
                             std::size_t rhs_size) noexcept {
    return detail::address_ranges_overlap(
        lhs_begin, lhs_size, rhs_begin, rhs_size);
}

[[nodiscard]] bool is_executable_protection(DWORD protect) noexcept {
    if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    switch (protect & 0xFFu) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] std::int64_t read_signed_displacement(const std::byte* bytes,
                                                     std::size_t size) noexcept {
    if (size == 1) {
        std::int8_t value = 0;
        std::memcpy(&value, bytes, sizeof(value));
        return value;
    }
    if (size == 2) {
        std::int16_t value = 0;
        std::memcpy(&value, bytes, sizeof(value));
        return value;
    }
    std::int32_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

[[nodiscard]] Status decode_block(const std::byte* code,
                                  std::size_t available,
                                  std::size_t required_length,
                                  std::uintptr_t source_address,
                                  DecodedBlock& out) noexcept {
    out = {};
    if (code == nullptr || required_length == 0 || required_length > kMaximumPatchBytes) {
        return fail(ErrorCode::InvalidArgument, "NativeInlineHook::decode_block");
    }

    const std::size_t decode_required_length = required_length;
    constexpr std::size_t kNoPaddingTarget = (std::numeric_limits<std::size_t>::max)();
    bool terminal_seen = false;
    std::size_t padding_until = kNoPaddingTarget;

    while (out.length < decode_required_length) {
        if (terminal_seen && padding_until == out.length) {
            terminal_seen = false;
            padding_until = kNoPaddingTarget;
        }
        if (out.instruction_count >= out.instructions.size() || out.length >= available) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::decode_block",
                        0,
                        "The entry point does not contain a complete relocatable instruction block");
        }

        DecodedInstruction instruction{};
        instruction.offset = out.length;

        detail::x86::DecodedInstruction decoded{};
        if (!detail::x86::decode_instruction(
                code + out.length, available - out.length, kNativeDecoderMode, decoded) ||
            decoded.length == 0 || decoded.length > 15) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "Tessera::x86::decode_instruction",
                        0,
                        "The entry point contains an invalid, truncated, or unsupported instruction");
        }

        instruction.length = decoded.length;
        instruction.opcode = decoded.opcode;
        instruction.opcode2 = decoded.opcode2;
        instruction.modrm_reg = decoded.modrm_reg;

        if (decoded.has_relative_operand) {
            instruction.relative_size = decoded.relative_size;
            if (instruction.relative_size != 1 && instruction.relative_size != 2 &&
                instruction.relative_size != 4) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::decode_block",
                            0,
                            "The relative branch operand has an unsupported size");
            }
            instruction.relative_offset = decoded.relative_offset;
            const std::int64_t displacement =
                read_signed_displacement(code + out.length + instruction.relative_offset,
                                         instruction.relative_size);
#if defined(TESSERA_HOOK_X64)
            instruction.relative_target =
                static_cast<std::int64_t>(source_address + out.length + instruction.length) +
                displacement;
#else
            const std::uint32_t next =
                static_cast<std::uint32_t>(source_address + out.length + instruction.length);
            instruction.relative_target = static_cast<std::uint32_t>(
                next + static_cast<std::uint32_t>(displacement));
#endif
            instruction.has_relative_operand = true;
        }

#if defined(TESSERA_HOOK_X64)
        if (decoded.has_rip_relative_operand) {
            instruction.rip_displacement_offset = decoded.rip_displacement_offset;
            std::int32_t displacement = 0;
            std::memcpy(&displacement,
                        code + out.length + instruction.rip_displacement_offset,
                        sizeof(displacement));
            instruction.rip_target =
                static_cast<std::int64_t>(source_address + out.length + instruction.length) +
                displacement;
            instruction.has_rip_relative_operand = true;
        }
#endif

        
        if (out.length + instruction.length > available ||
            out.length + instruction.length > kMaximumPatchBytes) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::decode_block",
                        0,
                        "The decoded entry point exceeds the readable or supported patch window");
        }

        const std::size_t instruction_end = out.length + instruction.length;
        if (terminal_seen) {
            if (!is_padding_instruction(instruction) ||
                (padding_until != kNoPaddingTarget && instruction_end > padding_until)) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::decode_block",
                            0,
                            "A terminal instruction is followed by bytes that are not safe padding");
            }
        } else if (is_terminal_instruction(instruction)) {
            terminal_seen = true;
            if ((instruction.opcode == 0xE9 || instruction.opcode == 0xEB) &&
                instruction.has_relative_operand) {
                const std::int64_t source_begin = static_cast<std::int64_t>(source_address);
                if (instruction.relative_target >= source_begin &&
                    instruction.relative_target < source_begin +
                        static_cast<std::int64_t>(required_length)) {
                    const auto target_offset = static_cast<std::size_t>(
                        instruction.relative_target - source_begin);
                    if (target_offset > instruction_end) {
                        // A forward unconditional branch into the guaranteed
                        // patch window may jump over padding. Never decode
                        // arbitrary bytes between the jump and its target.
                        padding_until = target_offset;
                    }
                    if (target_offset == instruction_end) {
                        terminal_seen = false;
                    }
                }
            }
        }

        instruction.trampoline_offset = out.trampoline_length;
        instruction.relocated_length = instruction.length;
        if (instruction.has_relative_operand && instruction.opcode == 0xE8) {
            const std::int64_t next_instruction =
                static_cast<std::int64_t>(source_address + out.length + instruction.length);
            if (instruction.relative_target == next_instruction) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::decode_block",
                            0,
                            "CALL to the next instruction materializes the original PC and cannot be relocated transparently");
            }
        }

        if (instruction.has_relative_operand && instruction.relative_size == 1) {
            if (instruction.opcode == 0xEB) {
                if (instruction.length != 2) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::decode_block",
                                0,
                                "Prefixed short JMP instructions are not relocated");
                }
                // Short unconditional JMP becomes a near JMP (E9 rel32).
                instruction.relocated_length = 5;
            } else if (instruction.opcode >= 0x70 && instruction.opcode <= 0x7F) {
                if (instruction.length != 2) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::decode_block",
                                0,
                                "Prefixed short Jcc instructions are not relocated");
                }
                // Short Jcc becomes the equivalent two-byte opcode + rel32 form.
                instruction.relocated_length = 6;
            } else if (instruction.opcode >= 0xE0 && instruction.opcode <= 0xE3) {
                // LOOP/LOOPE/LOOPNE/JCXZ cannot be replaced by a simple Jcc:
                // preserve the original instruction and branch to a nearby
                // rel32 dispatch stub without changing flags or address-size prefixes.
                instruction.relocated_length = instruction.length + 10;
            } else {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::decode_block",
                            0,
                            "This short relative branch opcode is not supported");
            }
        }

        out.trampoline_length += instruction.relocated_length;
        out.instructions[out.instruction_count++] = instruction;
        out.length += instruction.length;
    }

    return ok();
}

[[nodiscard]] void* allocate_trampoline(std::uintptr_t target,
                                        std::size_t allocation_size) noexcept {
#if defined(TESSERA_HOOK_X86)
    (void)target;
    return ::VirtualAlloc(nullptr,
                          allocation_size,
                          MEM_RESERVE | MEM_COMMIT,
                          PAGE_READWRITE);
#else
    SYSTEM_INFO system_info{};
    ::GetSystemInfo(&system_info);
    const std::uintptr_t granularity =
        static_cast<std::uintptr_t>(system_info.dwAllocationGranularity);
    if (granularity == 0) {
        return nullptr;
    }

    constexpr std::uintptr_t kSearchRadius = 0x70000000u;
    const std::uintptr_t aligned_target = target - (target % granularity);
    for (std::uintptr_t distance = granularity; distance <= kSearchRadius; distance += granularity) {
        if (aligned_target <= (std::numeric_limits<std::uintptr_t>::max)() - distance) {
            const std::uintptr_t candidate = aligned_target + distance;
            void* allocation = ::VirtualAlloc(reinterpret_cast<void*>(candidate),
                                              allocation_size,
                                              MEM_RESERVE | MEM_COMMIT,
                                              PAGE_READWRITE);
            if (allocation != nullptr) {
                return allocation;
            }
        }
        if (aligned_target > distance) {
            const std::uintptr_t candidate = aligned_target - distance;
            void* allocation = ::VirtualAlloc(reinterpret_cast<void*>(candidate),
                                              allocation_size,
                                              MEM_RESERVE | MEM_COMMIT,
                                              PAGE_READWRITE);
            if (allocation != nullptr) {
                return allocation;
            }
        }
    }
    return nullptr;
#endif
}

void write_absolute_jump(std::byte* destination, std::uintptr_t target) noexcept {
    destination[0] = std::byte{0xFF};
    destination[1] = std::byte{0x25};
    for (std::size_t i = 2; i < 6; ++i) {
        destination[i] = std::byte{0};
    }
    const std::uint64_t address = static_cast<std::uint64_t>(target);
    std::memcpy(destination + 6, &address, sizeof(address));
}

[[nodiscard]] bool write_relative_jump(std::byte* destination,
                                       std::uintptr_t instruction_address,
                                       std::uintptr_t target) noexcept {
    destination[0] = std::byte{0xE9};
#if defined(TESSERA_HOOK_X64)
    const std::int64_t displacement =
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(instruction_address + 5);
    if (displacement < (std::numeric_limits<std::int32_t>::min)() ||
        displacement > (std::numeric_limits<std::int32_t>::max)()) {
        return false;
    }
    const auto relative = static_cast<std::int32_t>(displacement);
    std::memcpy(destination + 1, &relative, sizeof(relative));
#else
    const auto relative = static_cast<std::uint32_t>(target) -
                          static_cast<std::uint32_t>(instruction_address + 5);
    std::memcpy(destination + 1, &relative, sizeof(relative));
#endif
    return true;
}

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

[[nodiscard]] bool write_relative32(std::byte* field,
                                    std::uintptr_t next_instruction,
                                    std::int64_t destination) noexcept {
#if defined(TESSERA_HOOK_X64)
    const std::int64_t displacement =
        destination - static_cast<std::int64_t>(next_instruction);
    if (displacement < (std::numeric_limits<std::int32_t>::min)() ||
        displacement > (std::numeric_limits<std::int32_t>::max)()) {
        return false;
    }
    const auto value = static_cast<std::int32_t>(displacement);
    std::memcpy(field, &value, sizeof(value));
#else
    const auto value = static_cast<std::uint32_t>(destination) -
                       static_cast<std::uint32_t>(next_instruction);
    std::memcpy(field, &value, sizeof(value));
#endif
    return true;
}


#if defined(TESSERA_HOOK_X64)

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
    const DecodedBlock& block,
    std::uint8_t& trampoline_offset) noexcept {
    if (source_offset < entry_prefix_size) {
        return false;
    }
    const std::size_t patch_offset =
        static_cast<std::size_t>(source_offset) - entry_prefix_size;
    if (patch_offset > block.length) {
        return false;
    }

    if (patch_offset == 0u) {
        trampoline_offset = static_cast<std::uint8_t>(kTrampolineEntryPrefixSize);
        return true;
    }
    for (std::size_t index = 0; index < block.instruction_count; ++index) {
        const auto& instruction = block.instructions[index];
        if (instruction.offset + instruction.length == patch_offset) {
            const std::size_t mapped =
                kTrampolineEntryPrefixSize + instruction.trampoline_offset +
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

[[nodiscard]] Status prepare_trampoline_unwind(
    NativeHookState& state,
    std::size_t entry_prefix_size,
    const DecodedBlock& block) noexcept {
    auto* const allocation = static_cast<std::byte*>(state.allocation);
    auto* const unwind_info = reinterpret_cast<NativeUnwindInfo*>(
        allocation + kTrampolineUnwindInfoOffset);
    std::memset(unwind_info, 0, kMaximumUnwindInfoBytes);

    DWORD64 image_base = 0;
    const DWORD64 target_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(state.target));
    PRUNTIME_FUNCTION source_function =
        ::RtlLookupFunctionEntry(target_address, &image_base, nullptr);

    if (source_function == nullptr) {
        if (!is_leaf_safe_block(state.original_bytes.data(), block)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "No source unwind record exists and the stolen instructions are not provably leaf-safe");
        }
        unwind_info->VersionAndFlags = 1u;
        unwind_info->SizeOfProlog = 0u;
        unwind_info->CountOfCodes = 0u;
        unwind_info->FrameRegisterAndOffset = 0u;
    } else {
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

        const auto* const source_info =
            reinterpret_cast<const NativeUnwindInfo*>(image_base + source_function->UnwindData);
        if ((source_info->VersionAndFlags & 0x07u) != 1u ||
            (source_info->VersionAndFlags >> 3u) != 0u) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::unwind",
                        0,
                        "Only version-1 unwind records without handlers or chained records are supported");
        }

        const std::size_t source_patch_end = entry_prefix_size + block.length;
        std::size_t input_slot = 0u;
        std::size_t output_slot = 0u;
        std::uint8_t previous_code_offset = (std::numeric_limits<std::uint8_t>::max)();
        bool source_frame_setup = false;
        bool copied_frame_setup = false;
        while (input_slot < source_info->CountOfCodes) {
            const NativeUnwindCode& source_code = source_info->UnwindCode[input_slot];
            std::size_t slots = 0u;
            if (source_code.CodeOffset == 0u ||
                !unwind_slot_count(source_code, slots) ||
                slots > static_cast<std::size_t>(source_info->CountOfCodes) - input_slot ||
                source_code.CodeOffset > previous_code_offset ||
                source_code.CodeOffset > source_info->SizeOfProlog) {
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
                                            block,
                                            mapped_offset) ||
                    output_slot + slots > 255u) {
                    return fail(ErrorCode::UnsupportedInstruction,
                                "NativeInlineHook::unwind",
                                0,
                                "A source unwind operation does not map to a relocated instruction boundary");
                }
                std::memcpy(&unwind_info->UnwindCode[output_slot],
                            &source_info->UnwindCode[input_slot],
                            slots * sizeof(NativeUnwindCode));
                unwind_info->UnwindCode[output_slot].CodeOffset = mapped_offset;
                if ((source_code.Operation & 0x0Fu) == kUnwindOpSetFpReg) {
                    copied_frame_setup = true;
                }
                output_slot += slots;
            }
            input_slot += slots;
        }

        std::uint8_t mapped_prolog_size = 0u;
        if (source_info->SizeOfProlog <= entry_prefix_size) {
            mapped_prolog_size = source_info->SizeOfProlog;
        } else if (source_info->SizeOfProlog <= source_patch_end) {
            if (!map_unwind_code_offset(source_info->SizeOfProlog,
                                        entry_prefix_size,
                                        block,
                                        mapped_prolog_size)) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::unwind",
                            0,
                            "The end of the source prologue does not map to a relocated instruction boundary");
            }
        } else {
            const std::size_t relocated_end =
                kTrampolineEntryPrefixSize + block.trampoline_length;
            if (relocated_end > (std::numeric_limits<std::uint8_t>::max)()) {
                return fail(ErrorCode::UnsupportedInstruction, "NativeInlineHook::unwind");
            }
            mapped_prolog_size = static_cast<std::uint8_t>(relocated_end);
        }

        const unsigned int source_frame_register =
            source_info->FrameRegisterAndOffset & 0x0Fu;
        const unsigned int source_frame_offset =
            source_info->FrameRegisterAndOffset >> 4u;
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
            unwind_info->FrameRegisterAndOffset = source_info->FrameRegisterAndOffset;
        }

        unwind_info->VersionAndFlags = 1u;
        unwind_info->SizeOfProlog = mapped_prolog_size;
        unwind_info->CountOfCodes = static_cast<UCHAR>(output_slot);
    }

    state.unwind_function.BeginAddress = 0u;
    state.unwind_function.EndAddress = static_cast<DWORD>(
        kTrampolineEntryPrefixSize + block.trampoline_length + kReturnJumpSize);
    state.unwind_function.UnwindData = static_cast<DWORD>(kTrampolineUnwindInfoOffset);
    return ok();
}

[[nodiscard]] Status register_trampoline_unwind(
    NativeHookState& state) noexcept {
    // The UNWIND_INFO bytes must already be finalized while the trampoline
    // allocation is writable. This function only publishes the read-only data.
    if (!::RtlAddFunctionTable(
            &state.unwind_function,
            1u,
            static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(state.allocation)))) {
        return fail(ErrorCode::IoError,
                    "RtlAddFunctionTable",
                    ::GetLastError(),
                    "Windows rejected the generated trampoline runtime-function record");
    }
    state.unwind_registered = true;
    return ok();
}

#endif // TESSERA_HOOK_X64

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

class SuspendedThreads {
public:
    SuspendedThreads() noexcept = default;
    SuspendedThreads(const SuspendedThreads&) = delete;
    SuspendedThreads& operator=(const SuspendedThreads&) = delete;
    SuspendedThreads(SuspendedThreads&& other) noexcept
        : thread_list_(std::move(other.thread_list_)),
          suspended_(std::move(other.suspended_)),
          policy_(other.policy_) {}
    SuspendedThreads& operator=(SuspendedThreads&&) = delete;

    ~SuspendedThreads() noexcept { resume_all(); }

    [[nodiscard]] static Result<SuspendedThreads> acquire(ThreadPolicy policy) {
        SuspendedThreads result{};
        result.policy_ = policy;
        if (policy == ThreadPolicy::None) {
            return result;
        }

        auto list = platform::windows::ScopedThreadList::collect_other_threads(policy);
        if (!list) {
            return std::unexpected(list.error());
        }
        result.thread_list_ = std::move(*list);

        try {
            result.suspended_.reserve(result.thread_list_.handles().size());
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "SuspendedThreads::acquire");
        }

        for (void* raw_handle : result.thread_list_.handles()) {
            const HANDLE thread = static_cast<HANDLE>(raw_handle);
            if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
                const DWORD error = ::GetLastError();
                if (policy == ThreadPolicy::SuspendOthersStrict) {
                    return fail(ErrorCode::ThreadEnumerationFailed,
                                "SuspendThread",
                                error,
                                "Strict thread suspension failed");
                }
                continue;
            }
            result.suspended_.push_back(thread);
        }
        return result;
    }

    void resume() noexcept { resume_all(); }

    [[nodiscard]] Status ensure_outside(std::uintptr_t begin,
                                        std::size_t size,
                                        std::uintptr_t second_begin = 0,
                                        std::size_t second_size = 0) const noexcept {
        if (policy_ == ThreadPolicy::None) {
            return ok();
        }
        for (HANDLE thread : suspended_) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL;
            if (!::GetThreadContext(thread, &context)) {
                const DWORD error = ::GetLastError();
                if (policy_ == ThreadPolicy::SuspendOthersStrict) {
                    return fail(ErrorCode::ThreadEnumerationFailed,
                                "GetThreadContext",
                                error,
                                "Thread context query failed");
                }
                continue;
            }
#if defined(TESSERA_HOOK_X64)
            const std::uintptr_t instruction_pointer =
                static_cast<std::uintptr_t>(context.Rip);
#else
            const std::uintptr_t instruction_pointer =
                static_cast<std::uintptr_t>(context.Eip);
#endif
            if (detail::address_range_contains(begin, size, instruction_pointer) ||
                detail::address_range_contains(second_begin, second_size, instruction_pointer)) {
                return fail(ErrorCode::Conflict,
                            "NativeInlineHook::thread_ip",
                            0,
                            "Thread is inside the patch range");
            }
        }
        return ok();
    }

private:
    void resume_all() noexcept {
        for (auto it = suspended_.rbegin(); it != suspended_.rend(); ++it) {
            const HANDLE thread = *it;
            if (::ResumeThread(thread) == static_cast<DWORD>(-1)) {
                // A terminated thread object is signaled. Do not infer exit
                // from GetExitCodeThread: STILL_ACTIVE is also a valid thread
                // exit code and would make that check ambiguous.
                if (::WaitForSingleObject(thread, 0) != WAIT_OBJECT_0) {
                    std::terminate();
                }
            }
        }
        suspended_.clear();
    }

    platform::windows::ScopedThreadList thread_list_{};
    std::vector<HANDLE> suspended_{};
    ThreadPolicy policy_ = ThreadPolicy::SuspendOthersStrict;
};

[[nodiscard]] Result<DecodedBlock> prepare_prologue(void* target,
                                                    std::array<std::byte, kMaximumReadBytes>& bytes) noexcept {
    MEMORY_BASIC_INFORMATION region{};
    if (::VirtualQuery(target, &region, sizeof(region)) != sizeof(region)) {
        return fail(ErrorCode::OutOfRange, "VirtualQuery", ::GetLastError());
    }
    if (region.State != MEM_COMMIT || !is_executable_protection(region.Protect)) {
        return fail(ErrorCode::AccessDenied,
                    "NativeInlineHook::prepare_prologue",
                    0,
                    "Hook target is not committed executable memory");
    }

    const auto target_address = reinterpret_cast<std::uintptr_t>(target);
    const auto region_base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
    if (region.RegionSize > (std::numeric_limits<std::uintptr_t>::max)() - region_base) {
        return fail(ErrorCode::AddressOverflow, "VirtualQuery");
    }
    const std::uintptr_t region_end = region_base + region.RegionSize;
    if (target_address < region_base || target_address >= region_end) {
        return fail(ErrorCode::OutOfRange, "NativeInlineHook::prepare_prologue");
    }

    SYSTEM_INFO system_info{};
    ::GetSystemInfo(&system_info);
    const std::size_t page_size = static_cast<std::size_t>(system_info.dwPageSize);
    if (page_size == 0) {
        return fail(ErrorCode::IoError, "GetSystemInfo");
    }
    const std::size_t offset_in_page = target_address % page_size;
    const std::size_t bytes_to_page_end = page_size - offset_in_page;
    const std::size_t bytes_to_region_end = static_cast<std::size_t>(region_end - target_address);
    const std::size_t readable = (std::min)({bytes.size(), bytes_to_page_end, bytes_to_region_end});
    if (readable < kEntryJumpSize) {
        return fail(ErrorCode::UnsupportedInstruction,
                    "NativeInlineHook::prepare_prologue",
                    0,
                    "The target prologue is too close to a page or region boundary");
    }

    SIZE_T bytes_read = 0;
    if (!::ReadProcessMemory(::GetCurrentProcess(),
                             target,
                             bytes.data(),
                             readable,
                             &bytes_read) ||
        bytes_read < kEntryJumpSize) {
        return fail(ErrorCode::PartialTransfer,
                    "ReadProcessMemory",
                    ::GetLastError(),
                    "Could not safely read the target prologue");
    }

#if defined(TESSERA_HOOK_X64)
    const bool has_ibt_landing_pad =
        bytes[0] == std::byte{0xF3} && bytes[1] == std::byte{0x0F} &&
        bytes[2] == std::byte{0x1E} && bytes[3] == std::byte{0xFA};
#else
    const bool has_ibt_landing_pad =
        bytes[0] == std::byte{0xF3} && bytes[1] == std::byte{0x0F} &&
        bytes[2] == std::byte{0x1E} && bytes[3] == std::byte{0xFB};
#endif
    const std::size_t entry_prefix_size = has_ibt_landing_pad ? 4u : 0u;
    if (bytes_read < entry_prefix_size + kEntryJumpSize) {
        return fail(ErrorCode::UnsupportedInstruction,
                    "NativeInlineHook::prepare_prologue",
                    0,
                    "The target landing pad leaves too few readable bytes for the entry patch");
    }

    const std::byte* const patch_code = bytes.data() + entry_prefix_size;
    if (patch_code[0] == std::byte{0xE9} ||
        (patch_code[0] == std::byte{0xFF} && patch_code[1] == std::byte{0x25})) {
        return fail(ErrorCode::Conflict,
                    "NativeInlineHook::prepare_prologue",
                    0,
                    "The target already begins with a common jump-thunk encoding");
    }

    DecodedBlock block{};
    auto status = decode_block(patch_code,
                               static_cast<std::size_t>(bytes_read) - entry_prefix_size,
                               kEntryJumpSize,
                               target_address + entry_prefix_size,
                               block);
    if (!status) {
        return std::unexpected(status.error());
    }
    block.entry_prefix_size = entry_prefix_size;
    return block;
}

struct Win32PatchWriteOps {
    DWORD last_error_code = ERROR_SUCCESS;

    [[nodiscard]] bool protect(void* target,
                               std::size_t size,
                               DWORD protection,
                               DWORD* previous) noexcept {
        DWORD ignored = 0;
        if (!::VirtualProtect(target, size, protection,
                              previous != nullptr ? previous : &ignored)) {
            last_error_code = ::GetLastError();
            return false;
        }
        return true;
    }

    void copy(void* target, const std::byte* source, std::size_t size) noexcept {
        std::memcpy(target, source, size);
    }

    [[nodiscard]] bool flush(void* target, std::size_t size) noexcept {
        if (!::FlushInstructionCache(::GetCurrentProcess(), target, size)) {
            last_error_code = ::GetLastError();
            return false;
        }
        return true;
    }

    [[nodiscard]] DWORD last_error() const noexcept { return last_error_code; }
};

[[nodiscard]] Status write_target_bytes(void* target,
                                        const std::byte* bytes,
                                        const std::byte* rollback_bytes,
                                        std::size_t size,
                                        DWORD restore_protection,
                                        DWORD* original_protection = nullptr) noexcept {
    Win32PatchWriteOps ops{};
    unsigned long native_error = ERROR_SUCCESS;
    const auto outcome = detail::execute_patch_write(
        ops,
        target,
        bytes,
        rollback_bytes,
        size,
        static_cast<DWORD>(PAGE_EXECUTE_READWRITE),
        restore_protection,
        original_protection,
        native_error);

    switch (outcome) {
        case detail::PatchWriteOutcome::Success:
            return ok();
        case detail::PatchWriteOutcome::InitialProtectionFailure:
            return fail(ErrorCode::ProtectionFailed,
                        "VirtualProtect",
                        static_cast<std::uint32_t>(native_error));
        case detail::PatchWriteOutcome::FlushRolledBack:
            return fail(ErrorCode::IoError,
                        "FlushInstructionCache",
                        static_cast<std::uint32_t>(native_error),
                        "The attempted write was rolled back to its prior bytes");
        case detail::PatchWriteOutcome::ProtectionRolledBack:
            return fail(ErrorCode::ProtectionRestoreFailed,
                        "VirtualProtect(restore)",
                        static_cast<std::uint32_t>(native_error),
                        "The attempted write was rolled back to its prior bytes");
        case detail::PatchWriteOutcome::FatalRollback:
            // Returning would expose code with unconfirmed instruction-cache
            // state or page protection. Fail-fast is the only safe policy.
            std::terminate();
    }
    std::terminate();
}

class NativeInlineHookBackend final : public HookBackend {
public:
    [[nodiscard]] bool available() const noexcept override { return true; }

    [[nodiscard]] Result<HookToken> attach(Address target,
                                           void* detour,
                                           const HookOptions& options) override {
        if (target.is_null() || detour == nullptr) {
            return fail(ErrorCode::InvalidArgument, "NativeInlineHook::attach");
        }
        if (!is_valid_thread_policy(options.threads)) {
            return fail(ErrorCode::InvalidArgument,
                        "NativeInlineHook::attach",
                        0,
                        "Unknown thread coordination policy");
        }
        if constexpr (sizeof(std::uintptr_t) == 4) {
            if (target.value() > (std::numeric_limits<std::uintptr_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "NativeInlineHook::attach");
            }
        }
        const auto target_address = static_cast<std::uintptr_t>(target.value());
        if (target_address == reinterpret_cast<std::uintptr_t>(detour)) {
            return fail(ErrorCode::InvalidArgument, "NativeInlineHook::attach", 0, "Target and detour must differ");
        }

        MEMORY_BASIC_INFORMATION detour_region{};
        if (::VirtualQuery(detour, &detour_region, sizeof(detour_region)) !=
            sizeof(detour_region)) {
            return fail(ErrorCode::OutOfRange,
                        "VirtualQuery(detour)",
                        ::GetLastError(),
                        "Could not query the detour address");
        }
        if (detour_region.State != MEM_COMMIT ||
            !is_executable_protection(detour_region.Protect)) {
            return fail(ErrorCode::AccessDenied,
                        "NativeInlineHook::attach",
                        0,
                        "The detour must point to committed executable memory in this process");
        }

        if (target_address > (std::numeric_limits<std::uintptr_t>::max)() -
                                 (kMaximumPatchBytes + 4u)) {
            return fail(ErrorCode::AddressOverflow, "NativeInlineHook::attach");
        }

        platform::windows::ProcessWideHookLock lock{};
        if (!lock.acquired()) {
            return fail(ErrorCode::IoError, "ProcessWideHookLock", ::GetLastError());
        }

        auto& registry = active_native_hooks();
        for (const NativeHookState* active : registry) {
            const auto active_begin = reinterpret_cast<std::uintptr_t>(active->patch_target);
            if (target_address >= active_begin &&
                target_address - active_begin < active->patch_size) {
                return fail(ErrorCode::Conflict,
                            "NativeInlineHook::attach",
                            0,
                            "The requested entry point is inside an installed native hook patch");
            }
        }

        std::unique_ptr<NativeHookState> state;
        try {
            state = std::make_unique<NativeHookState>();
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "NativeInlineHook::attach");
        }
        state->target = reinterpret_cast<void*>(target_address);
        state->detour = detour;
        state->allocation_size = kTrampolineAllocationSize;

        std::array<std::byte, kMaximumReadBytes> source_bytes{};
        auto block_result = prepare_prologue(state->target, source_bytes);
        if (!block_result) {
            return std::unexpected(block_result.error());
        }
        const DecodedBlock& block = *block_result;
        const auto patch_address = target_address + block.entry_prefix_size;
        state->patch_target = reinterpret_cast<void*>(patch_address);
        state->patch_size = block.length;

        const auto detour_address = reinterpret_cast<std::uintptr_t>(detour);
        const auto overwritten_end = patch_address + block.length;
        if (detour_address >= target_address && detour_address < overwritten_end) {
            return fail(ErrorCode::InvalidArgument,
                        "NativeInlineHook::attach",
                        0,
                        "The detour address lies inside the entry bytes owned by this hook");
        }
        if (block.length > state->original_bytes.size()) {
            return fail(ErrorCode::UnsupportedInstruction, "NativeInlineHook::attach");
        }

        for (const NativeHookState* active : registry) {
            const auto active_begin = reinterpret_cast<std::uintptr_t>(active->patch_target);
            if (overlaps(patch_address, block.length, active_begin, active->patch_size)) {
                    return fail(ErrorCode::Conflict,
                            "NativeInlineHook::attach",
                            0,
                            "The requested entry-point patch overlaps an installed native hook");
            }
        }

        // Reserve registry capacity before changing executable memory. Once the
        // target patch commits, recording ownership is therefore allocation-free.
        try {
            registry.reserve(registry.size() + 1);
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "NativeInlineHook::attach", 0,
                        "Could not reserve native hook registry capacity");
        }

        std::memcpy(state->original_bytes.data(),
                    source_bytes.data() + block.entry_prefix_size,
                    block.length);
        state->allocation = allocate_trampoline(patch_address, state->allocation_size);
        if (state->allocation == nullptr) {
            return fail(ErrorCode::OutOfMemory,
                        "VirtualAlloc(trampoline)",
                        ::GetLastError(),
                        "Could not reserve executable trampoline memory near the target");
        }
        state->trampoline = state->allocation;

        auto* trampoline_bytes = static_cast<std::byte*>(state->trampoline);
        std::memcpy(trampoline_bytes,
                    kTrampolineLandingPad.data(),
                    kTrampolineLandingPad.size());
        if (block.entry_prefix_size != 0) {
            std::memcpy(state->entry_prefix_bytes.data(),
                        source_bytes.data(),
                        block.entry_prefix_size);
        }
        // Every trampoline is an indirect-call-safe landing point, even when
        // the original target did not have an ENDBR instruction.
        std::byte* const trampoline_code =
            trampoline_bytes + kTrampolineEntryPrefixSize;
        const auto trampoline_code_address =
            reinterpret_cast<std::uintptr_t>(trampoline_code);
        auto relocation_status = relocate_instructions(state->original_bytes.data(),
                                                        patch_address,
                                                        trampoline_code,
                                                        trampoline_code_address,
                                                        block);
        if (!relocation_status) {
            return std::unexpected(relocation_status.error());
        }

        std::byte* const trampoline_return =
            trampoline_code + block.trampoline_length;
        if (!write_relative_jump(trampoline_return,
                                 reinterpret_cast<std::uintptr_t>(trampoline_return),
                                 patch_address + block.length)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::attach",
                        0,
                        "The trampoline return target is outside rel32 reach");
        }

#if defined(TESSERA_HOOK_X64)
        if (!write_relative_jump(state->patch_bytes.data(), patch_address, detour_address)) {
            // Keep the entry patch five bytes even when the detour is farther
            // than rel32 reach. The near relay performs the final absolute jump.
            state->relay = static_cast<std::byte*>(state->allocation) + kTrampolineRelayOffset;
            write_absolute_jump(static_cast<std::byte*>(state->relay), detour_address);
            if (!write_relative_jump(state->patch_bytes.data(),
                                     patch_address,
                                     reinterpret_cast<std::uintptr_t>(state->relay))) {
                return fail(ErrorCode::UnsupportedInstruction,
                            "NativeInlineHook::attach",
                            0,
                            "The near detour relay is outside entry rel32 reach");
            }
        }
#else
        if (!write_relative_jump(state->patch_bytes.data(),
                                 patch_address,
                                 reinterpret_cast<std::uintptr_t>(detour))) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "NativeInlineHook::attach",
                        0,
                        "The x86 relative branch target is outside the 32-bit address space");
        }
#endif

#if defined(TESSERA_HOOK_X64)
        // Build the unwind bytes while the allocation is still PAGE_READWRITE.
        // Registration itself is delayed until after the code/data are finalized.
        auto unwind_prepare_status = prepare_trampoline_unwind(
            *state, block.entry_prefix_size, block);
        if (!unwind_prepare_status) {
            return std::unexpected(unwind_prepare_status.error());
        }
#endif

        DWORD trampoline_protection = 0;
        if (!::VirtualProtect(state->allocation,
                              state->allocation_size,
                              PAGE_EXECUTE_READ,
                              &trampoline_protection) ||
            !::FlushInstructionCache(::GetCurrentProcess(), state->trampoline,
                                     kTrampolineEntryPrefixSize + block.trampoline_length +
                                         kReturnJumpSize)
#if defined(TESSERA_HOOK_X64)
            || (state->relay != nullptr &&
                !::FlushInstructionCache(::GetCurrentProcess(),
                                         state->relay,
                                         kAbsoluteJumpSize))
#endif
        ) {
            const DWORD error = ::GetLastError();
            return fail(ErrorCode::ProtectionFailed,
                        "VirtualProtect(trampoline)",
                        error,
                        "The trampoline or detour relay could not be made executable");
        }

#if defined(TESSERA_HOOK_X64)
        // Register unwind metadata before any entry patch can publish the
        // trampoline to another thread or to HookCore.
        auto unwind_status = register_trampoline_unwind(*state);
        if (!unwind_status) {
            return std::unexpected(unwind_status.error());
        }
#endif

        auto suspended_result = SuspendedThreads::acquire(options.threads);
        if (!suspended_result) {
            return std::unexpected(suspended_result.error());
        }
        SuspendedThreads suspended = std::move(*suspended_result);
        auto thread_status = suspended.ensure_outside(patch_address, block.length);
        const bool entry_prefix_changed =
            block.entry_prefix_size != 0 &&
            std::memcmp(state->target,
                        state->entry_prefix_bytes.data(),
                        block.entry_prefix_size) != 0;
        const bool patch_bytes_changed =
            std::memcmp(state->patch_target, state->original_bytes.data(), block.length) != 0;
        if (!thread_status || entry_prefix_changed || patch_bytes_changed) {
            suspended.resume();
            const Error error = thread_status
                                    ? make_error(ErrorCode::Conflict,
                                                 "NativeInlineHook::attach",
                                                 0,
                                                 "Target prologue or preserved landing pad changed")
                                    : thread_status.error();
            return std::unexpected(error);
        }

        std::fill(state->patch_bytes.begin() + static_cast<std::ptrdiff_t>(kEntryJumpSize),
                  state->patch_bytes.begin() + static_cast<std::ptrdiff_t>(block.length),
                  std::byte{0x90});

        auto patch_status = write_target_bytes(state->patch_target,
                                               state->patch_bytes.data(),
                                               state->original_bytes.data(),
                                               state->patch_size,
                                               0,
                                               &state->original_protection);
        if (!patch_status) {
            suspended.resume();
            return std::unexpected(patch_status.error());
        }

        // Capacity was reserved before patching while ProcessWideHookLock
        // was held, so this pointer insertion cannot allocate or throw.
        registry.push_back(state.get());

        return HookToken{
            .target = state->target,
            .detour = state->detour,
            .trampoline = state->trampoline,
            .threads = options.threads,
            .observer = options.observer,
            .backend_data = state.release(),
        };
    }

    [[nodiscard]] Status detach(HookToken& token) override {
        auto* state = static_cast<NativeHookState*>(token.backend_data);
        if (state == nullptr || state->target == nullptr || state->trampoline == nullptr) {
            return fail(ErrorCode::InvalidArgument,
                        "NativeInlineHook::detach",
                        0,
                        "The hook token does not belong to the native inline backend");
        }
        if (token.target != state->target || token.detour != state->detour ||
            token.trampoline != state->trampoline) {
            return fail(ErrorCode::Conflict,
                        "NativeInlineHook::detach",
                        0,
                        "The hook token was modified after installation");
        }
        if (!is_valid_thread_policy(token.threads)) {
            return fail(ErrorCode::InvalidArgument,
                        "NativeInlineHook::detach",
                        0,
                        "Unknown thread coordination policy in hook token");
        }

        platform::windows::ProcessWideHookLock lock{};
        if (!lock.acquired()) {
            return fail(ErrorCode::IoError, "ProcessWideHookLock", ::GetLastError());
        }
        auto& registry = active_native_hooks();
        const auto registry_entry = std::find(registry.begin(), registry.end(), state);
        if (registry_entry == registry.end()) {
            return fail(ErrorCode::Conflict,
                        "NativeInlineHook::detach",
                        0,
                        "The native hook is not registered as an active patch owner");
        }

        auto suspended_result = SuspendedThreads::acquire(token.threads);
        if (!suspended_result) {
            return std::unexpected(suspended_result.error());
        }
        SuspendedThreads suspended = std::move(*suspended_result);

        auto thread_status = suspended.ensure_outside(
            reinterpret_cast<std::uintptr_t>(state->patch_target),
            state->patch_size,
            reinterpret_cast<std::uintptr_t>(state->trampoline),
            state->allocation_size);
        if (!thread_status) {
            return thread_status;
        }

#if defined(TESSERA_HOOK_X64)
        if (!state->target_detached) {
#endif
            if (std::memcmp(state->patch_target,
                            state->patch_bytes.data(),
                            state->patch_size) != 0) {
                suspended.resume();
                return fail(ErrorCode::Conflict,
                            "NativeInlineHook::detach",
                            0,
                            "Target bytes changed");
            }

            auto restore_status = write_target_bytes(state->patch_target,
                                                     state->original_bytes.data(),
                                                     state->patch_bytes.data(),
                                                     state->patch_size,
                                                     state->original_protection);
            if (!restore_status) {
                return restore_status;
            }
#if defined(TESSERA_HOOK_X64)
            state->target_detached = true;
        }

        if (state->target_detached &&
            std::memcmp(state->patch_target,
                        state->original_bytes.data(),
                        state->patch_size) != 0) {
            // The first detach attempt already restored the entry but could not
            // unregister the function table. If another writer changed those
            // bytes before a retry, retain the trampoline/table and token.
            suspended.resume();
            return fail(ErrorCode::Conflict,
                        "NativeInlineHook::detach",
                        0,
                        "Target bytes changed after the entry patch was restored; unwind metadata remains registered");
        }

        if (state->unwind_registered &&
            !::RtlDeleteFunctionTable(&state->unwind_function)) {
            const DWORD error = ::GetLastError();
            // A failed unregister must not leave HookCore believing it has
            // detached while its target is still restored. Reinstall the entry
            // patch under the same suspended-thread window and retain the
            // function table + executable allocation for a retry.
            auto reattach_status = write_target_bytes(state->patch_target,
                                                      state->patch_bytes.data(),
                                                      state->original_bytes.data(),
                                                      state->patch_size,
                                                      state->original_protection);
            if (!reattach_status) {
                std::terminate();
            }
            state->target_detached = false;
            suspended.resume();
            return fail(ErrorCode::IoError,
                        "RtlDeleteFunctionTable",
                        error,
                        "The target patch was restored because Windows could not unregister the trampoline unwind table");
        }
        state->unwind_registered = false;
#endif

        suspended.resume();
        registry.erase(registry_entry);
        delete state;
        token.trampoline = nullptr;
        token.backend_data = nullptr;
        return ok();
    }
};

} // namespace

HookBackend& native_inline_hook_backend() noexcept {
    static NativeInlineHookBackend backend{};
    return backend;
}

} // namespace tessera
