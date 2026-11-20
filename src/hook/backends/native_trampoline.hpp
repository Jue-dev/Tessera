#pragma once

#include <cstddef>
#include <cstdint>
#include <Windows.h>

namespace tessera::detail::native_hook {

using VirtualAllocFn = decltype(&::VirtualAlloc);
using GetSystemInfoFn = decltype(&::GetSystemInfo);

[[nodiscard]] void* allocate_trampoline(
    std::uintptr_t target,
    std::size_t allocation_size,
    VirtualAllocFn virtual_alloc = &::VirtualAlloc,
    GetSystemInfoFn get_system_info = &::GetSystemInfo) noexcept;
void write_absolute_jump(std::byte* destination, std::uintptr_t target) noexcept;
[[nodiscard]] bool write_unwind_safe_tail(std::byte* destination,
                                          std::uintptr_t instruction_address,
                                          std::uintptr_t target) noexcept;
[[nodiscard]] bool write_relative_jump(std::byte* destination,
                                       std::uintptr_t instruction_address,
                                       std::uintptr_t target) noexcept;
[[nodiscard]] bool write_relative32(std::byte* field,
                                    std::uintptr_t next_instruction,
                                    std::int64_t destination) noexcept;

} // namespace tessera::detail::native_hook
