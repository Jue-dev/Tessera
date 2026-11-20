#pragma once

#include <cstddef>
#include <cstdint>

namespace tessera::detail::native_hook {

[[nodiscard]] void* allocate_trampoline(std::uintptr_t target, std::size_t allocation_size) noexcept;
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
