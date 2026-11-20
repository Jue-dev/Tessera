#include "native_trampoline.hpp"

#include <Windows.h>

#include <cstring>
#include <limits>

#if defined(_M_X64) || defined(__x86_64__)
    #define TESSERA_HOOK_X64 1
#elif defined(_M_IX86) || defined(__i386__)
    #define TESSERA_HOOK_X86 1
#else
    #error "Tessera native inline hooks support only x86 and x64."
#endif

namespace tessera::detail::native_hook {

[[nodiscard]] void* allocate_trampoline(std::uintptr_t target,
                          std::size_t allocation_size,
                          VirtualAllocFn virtual_alloc,
                          GetSystemInfoFn get_system_info) noexcept {
#if defined(TESSERA_HOOK_X86)
    (void)target;
    (void)get_system_info;
    return virtual_alloc(nullptr,
                         allocation_size,
                         MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE);
#else
    SYSTEM_INFO system_info{};
    get_system_info(&system_info);
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
            void* allocation = virtual_alloc(reinterpret_cast<void*>(candidate),
                                              allocation_size,
                                              MEM_RESERVE | MEM_COMMIT,
                                              PAGE_READWRITE);
            if (allocation != nullptr) {
                return allocation;
            }
        }
        if (aligned_target > distance) {
            const std::uintptr_t candidate = aligned_target - distance;
            void* allocation = virtual_alloc(reinterpret_cast<void*>(candidate),
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


[[nodiscard]] bool write_unwind_safe_tail(std::byte* destination,
                                       std::uintptr_t instruction_address,
                                       std::uintptr_t target) noexcept {
#if defined(TESSERA_HOOK_X64)
    // JE target; JNE target. Exactly one branch is taken for every flag state.
    // Unlike an unconditional JMP, neither instruction is an x64 epilog marker,
    // so RtlVirtualUnwind applies the trampoline's unwind metadata at this tail.
    destination[0] = std::byte{0x0F};
    destination[1] = std::byte{0x84};
    destination[6] = std::byte{0x0F};
    destination[7] = std::byte{0x85};
    const std::int64_t first_displacement =
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(instruction_address + 6u);
    const std::int64_t second_displacement =
        static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(instruction_address + 12u);
    if (first_displacement < (std::numeric_limits<std::int32_t>::min)() ||
        first_displacement > (std::numeric_limits<std::int32_t>::max)() ||
        second_displacement < (std::numeric_limits<std::int32_t>::min)() ||
        second_displacement > (std::numeric_limits<std::int32_t>::max)()) {
        return false;
    }
    const auto first_relative = static_cast<std::int32_t>(first_displacement);
    const auto second_relative = static_cast<std::int32_t>(second_displacement);
    std::memcpy(destination + 2, &first_relative, sizeof(first_relative));
    std::memcpy(destination + 8, &second_relative, sizeof(second_relative));
    return true;
#else
    destination[0] = std::byte{0xE9};
    const auto relative = static_cast<std::uint32_t>(target) -
                          static_cast<std::uint32_t>(instruction_address + 5u);
    std::memcpy(destination + 1, &relative, sizeof(relative));
    return true;
#endif
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




} // namespace tessera::detail::native_hook
