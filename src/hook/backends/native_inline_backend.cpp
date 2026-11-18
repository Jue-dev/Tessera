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
constexpr std::size_t kTrampolineAllocationSize =
    kTrampolineCodeCapacity + kAbsoluteJumpSize;
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

    ~NativeHookState() noexcept {
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
    return lhs_begin < rhs_begin + rhs_size && rhs_begin < lhs_begin + lhs_size;
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
        const std::uintptr_t end = begin + size;
        const std::uintptr_t second_end = second_begin + second_size;
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
            if ((instruction_pointer >= begin && instruction_pointer < end) ||
                (second_size != 0 && instruction_pointer >= second_begin &&
                 instruction_pointer < second_end)) {
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

        if (std::memcmp(state->patch_target, state->patch_bytes.data(), state->patch_size) != 0) {
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
