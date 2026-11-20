#pragma once

#include <Windows.h>
#include <array>
#include <cstddef>

namespace winmock {

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
extern int thread_next_calls;
extern int suspend_thread_fail_on_call;
extern DWORD suspend_thread_error;
extern DWORD get_thread_context_error;
extern int suspend_thread_calls;
extern int get_thread_context_calls;
extern int resume_thread_calls;
extern DWORD resume_thread_error;
extern DWORD wait_for_single_object_result;
extern LONG detour_update_error;
extern LONG detour_attach_error;
extern LONG detour_detach_error;
extern int detour_attach_calls;
extern int detour_detach_calls;
extern int detour_abort_calls;
extern std::array<std::byte, 64> process_memory;
extern DWORD process_memory_protect;
extern std::size_t max_read_chunk;
extern int flush_instruction_cache_calls;
extern USHORT process_machine;
extern USHORT native_machine;

void reset() noexcept;

} // namespace winmock
