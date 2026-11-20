#pragma once

#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdint>

namespace winmock {

enum class MemoryApiCall { VirtualProtectEx, WriteProcessMemory, FlushInstructionCache };
struct MemoryApiCallRecord {
    MemoryApiCall call{};
    std::uintptr_t address{};
    std::size_t size{};
    DWORD protection{};
};
extern std::array<MemoryApiCallRecord, 32> memory_api_call_log;
extern int memory_api_call_count;

enum class NativeApi { OpenProcess, GetProcessId, IsWow64Process2, GetExitCodeProcess, ReadProcessMemory, VirtualQueryEx, EnumProcessModulesEx, GetModuleInformation, GetModuleBaseNameW, GetModuleFileNameExW, GetModuleHandleW };
struct NativeApiCallRecord {
    NativeApi call{};
    std::uintptr_t handle{};
    std::uintptr_t argument1{};
    std::uintptr_t argument2{};
    std::uintptr_t argument3{};
};
extern std::array<NativeApiCallRecord, 64> native_api_call_log;
extern int native_api_call_count;
extern NativeApi fail_native_api;
extern int fail_native_api_on_call;
extern DWORD fail_native_api_error;
bool record_native_api_call(NativeApi call, HANDLE handle, std::uintptr_t a1 = 0,
                            std::uintptr_t a2 = 0, std::uintptr_t a3 = 0) noexcept;

enum class ModuleMode { Stable, Growing, Misaligned };
extern ModuleMode module_mode;
extern int module_calls;
extern DWORD last_error;
extern int thread_next_error;
extern DWORD last_open_thread_access;
extern DWORD snapshot_error;
extern DWORD thread_first_error;
extern DWORD open_thread_error;
extern int snapshot_calls;
extern int thread_first_calls;
extern int open_thread_calls;
extern int close_handle_calls;
extern int close_handle_fail_on_call;
extern DWORD close_handle_error;
extern int thread_count;
extern int snapshot_thread_count;
extern bool create_thread_during_suspend;
extern int create_threads_during_suspend_count;
extern int create_threads_during_enumeration_count;
extern int create_threads_during_context_count;
extern int thread_next_calls;
extern int suspend_thread_fail_on_call;
extern DWORD suspend_thread_error;
extern DWORD get_thread_context_error;
extern int suspend_thread_calls;
extern int get_thread_context_calls;
extern int resume_thread_calls;
extern DWORD resume_thread_error;
extern DWORD wait_for_single_object_result;
extern DWORD release_mutex_error;
extern int release_mutex_calls;
extern LONG detour_update_error;
extern LONG detour_attach_error;
extern LONG detour_detach_error;
extern int detour_attach_calls;
extern int detour_detach_calls;
extern int detour_abort_calls;
extern std::array<std::byte, 64> process_memory;
extern DWORD process_memory_protect;
extern std::size_t max_read_chunk;
extern int write_process_memory_calls;
extern int write_process_memory_fail_on_call;
extern int write_process_memory_fail_on_call_2;
extern DWORD write_process_memory_error;
extern std::size_t write_process_memory_partial_bytes;
extern int virtual_protect_calls;
extern int virtual_protect_fail_on_call;
extern DWORD virtual_protect_error;
extern int flush_instruction_cache_calls;
extern int flush_instruction_cache_fail_on_call;
extern DWORD flush_instruction_cache_error;
extern USHORT process_machine;
extern USHORT native_machine;

void reset() noexcept;

} // namespace winmock
