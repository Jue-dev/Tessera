#pragma once
#include "native_relocation.hpp"
#if defined(_M_X64) || defined(__x86_64__)
#include <Windows.h>
namespace tessera::detail::native_hook {
inline constexpr std::size_t kTrampolineUnwindInfoOffset = 272u;
inline constexpr std::size_t kMaximumUnwindInfoBytes = 516u;
[[nodiscard]] Status prepare_trampoline_unwind(
    void* allocation_base, void* target, const std::byte* original_code,
    std::size_t entry_prefix_size, const DecodedBlock& block,
    std::size_t trampoline_entry_prefix_size, std::size_t return_jump_size,
    std::size_t unwind_info_offset, RUNTIME_FUNCTION& unwind_function) noexcept;
[[nodiscard]] Status register_trampoline_unwind(
    RUNTIME_FUNCTION& unwind_function, bool& unwind_registered,
    void* allocation_base) noexcept;
[[nodiscard]] bool unregister_trampoline_unwind(
    RUNTIME_FUNCTION& unwind_function, bool& unwind_registered) noexcept;
} // namespace tessera::detail::native_hook
#endif // x64
