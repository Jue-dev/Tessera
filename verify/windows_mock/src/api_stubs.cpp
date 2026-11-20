#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <detours.h>
#include "api_stubs.hpp"

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <cstdint>

namespace winmock {

ModuleMode module_mode = ModuleMode::Stable;
int module_calls = 0;
DWORD last_error = NO_ERROR;
int thread_next_error = static_cast<int>(ERROR_NO_MORE_FILES);
DWORD last_open_thread_access = 0;
DWORD snapshot_error = NO_ERROR;
DWORD thread_first_error = NO_ERROR;
DWORD open_thread_error = NO_ERROR;
int snapshot_calls = 0;
int thread_first_calls = 0;
int open_thread_calls = 0;
int close_handle_calls = 0;
int thread_count = 1;
int thread_next_calls = 0;
int suspend_thread_fail_on_call = 0;
DWORD suspend_thread_error = NO_ERROR;
DWORD get_thread_context_error = NO_ERROR;
int suspend_thread_calls = 0;
int get_thread_context_calls = 0;
int resume_thread_calls = 0;
DWORD resume_thread_error = NO_ERROR;
DWORD wait_for_single_object_result = WAIT_OBJECT_0;
LONG detour_update_error = NO_ERROR;
LONG detour_attach_error = NO_ERROR;
LONG detour_detach_error = NO_ERROR;
int detour_attach_calls = 0;
int detour_detach_calls = 0;
int detour_abort_calls = 0;
std::array<std::byte, 64> process_memory{};
DWORD process_memory_protect = PAGE_EXECUTE_READ;
std::size_t max_read_chunk = static_cast<std::size_t>(-1);
int flush_instruction_cache_calls = 0;
USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
USHORT native_machine = IMAGE_FILE_MACHINE_AMD64;

void reset() noexcept {
    module_mode = ModuleMode::Stable;
    module_calls = 0;
    last_error = NO_ERROR;
    thread_next_error = static_cast<int>(ERROR_NO_MORE_FILES);
    last_open_thread_access = 0;
    snapshot_error = NO_ERROR;
    thread_first_error = NO_ERROR;
    open_thread_error = NO_ERROR;
    snapshot_calls = 0;
    thread_first_calls = 0;
    open_thread_calls = 0;
    close_handle_calls = 0;
    thread_count = 1;
    thread_next_calls = 0;
    suspend_thread_fail_on_call = 0;
    suspend_thread_error = NO_ERROR;
    get_thread_context_error = NO_ERROR;
    suspend_thread_calls = 0;
    get_thread_context_calls = 0;
    resume_thread_calls = 0;
    detour_update_error = NO_ERROR;
    detour_attach_error = NO_ERROR;
    detour_detach_error = NO_ERROR;
    detour_attach_calls = 0;
    detour_detach_calls = 0;
    detour_abort_calls = 0;
    for (std::size_t i = 0; i < process_memory.size(); ++i) {
        process_memory[i] = static_cast<std::byte>(i);
    }
    process_memory_protect = PAGE_EXECUTE_READ;
    max_read_chunk = static_cast<std::size_t>(-1);
    flush_instruction_cache_calls = 0;
    process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    native_machine = IMAGE_FILE_MACHINE_AMD64;
}

} // namespace winmock

DWORD GetLastError() noexcept { return winmock::last_error; }
void SetLastError(DWORD value) noexcept { winmock::last_error = value; }
HANDLE GetCurrentProcess() noexcept { return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(1)); }
DWORD GetCurrentProcessId() noexcept { return 42; }
HANDLE GetCurrentThread() noexcept { return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(2)); }
DWORD GetCurrentThreadId() noexcept { return 41; }
BOOL CloseHandle(HANDLE) noexcept { ++winmock::close_handle_calls; return TRUE; }
BOOL IsWow64Process2(HANDLE, USHORT* process_machine, USHORT* native_machine) noexcept {
    *process_machine = winmock::process_machine;
    *native_machine = winmock::native_machine;
    return TRUE;
}
void GetNativeSystemInfo(SYSTEM_INFO* info) noexcept {
    info->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    info->lpMaximumApplicationAddress = reinterpret_cast<void*>(0x7fffffffffffULL);
}
HANDLE OpenProcess(DWORD, BOOL, DWORD) noexcept { return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x44)); }
BOOL GetExitCodeProcess(HANDLE, DWORD* code) noexcept { *code = STILL_ACTIVE; return TRUE; }
DWORD GetProcessId(HANDLE) noexcept { return 42; }
BOOL ReadProcessMemory(HANDLE, LPCVOID address, LPVOID buffer, SIZE_T requested, SIZE_T* transferred) noexcept {
    constexpr std::uintptr_t base = 0x1000;
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (value < base || value - base >= winmock::process_memory.size()) {
        *transferred = 0;
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const std::size_t offset = static_cast<std::size_t>(value - base);
    const std::size_t count = (std::min)({requested, winmock::process_memory.size() - offset, winmock::max_read_chunk});
    std::memcpy(buffer, winmock::process_memory.data() + offset, count);
    *transferred = count;
    if (count != requested) { SetLastError(ERROR_PARTIAL_COPY); return FALSE; }
    return TRUE;
}
BOOL WriteProcessMemory(HANDLE, LPVOID address, LPCVOID buffer, SIZE_T requested, SIZE_T* transferred) noexcept {
    constexpr std::uintptr_t base = 0x1000;
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (value < base || value - base >= winmock::process_memory.size()) {
        *transferred = 0;
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const std::size_t offset = static_cast<std::size_t>(value - base);
    const std::size_t count = (std::min)(requested, winmock::process_memory.size() - offset);
    std::memcpy(winmock::process_memory.data() + offset, buffer, count);
    *transferred = count;
    if (count != requested) { SetLastError(ERROR_PARTIAL_COPY); return FALSE; }
    return TRUE;
}
SIZE_T VirtualQueryEx(HANDLE, LPCVOID address, MEMORY_BASIC_INFORMATION* mbi, SIZE_T) noexcept {
    constexpr std::uintptr_t base = 0x1000;
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (value < base || value - base >= winmock::process_memory.size()) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    mbi->BaseAddress = reinterpret_cast<void*>(base);
    mbi->AllocationBase = reinterpret_cast<void*>(base);
    mbi->AllocationProtect = PAGE_EXECUTE_READ;
    mbi->RegionSize = winmock::process_memory.size();
    mbi->State = MEM_COMMIT;
    mbi->Protect = winmock::process_memory_protect;
    mbi->Type = MEM_PRIVATE;
    return sizeof(*mbi);
}
BOOL VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD new_protection, DWORD* old_protection) noexcept {
    *old_protection = winmock::process_memory_protect;
    winmock::process_memory_protect = new_protection;
    return TRUE;
}
BOOL FlushInstructionCache(HANDLE, LPCVOID, SIZE_T) noexcept { ++winmock::flush_instruction_cache_calls; return TRUE; }
int CompareStringOrdinal(LPCWCH a, int alen, LPCWCH b, int blen, BOOL ignore_case) noexcept {
    if (alen != blen) return 0;
    for (int i = 0; i < alen; ++i) {
        wchar_t ac = a[i], bc = b[i];
        if (ignore_case) { ac = static_cast<wchar_t>(std::towlower(ac)); bc = static_cast<wchar_t>(std::towlower(bc)); }
        if (ac != bc) return 0;
    }
    return CSTR_EQUAL;
}
BOOL EnumProcessModulesEx(HANDLE, HMODULE* modules, DWORD bytes, DWORD* needed, DWORD) noexcept {
    ++winmock::module_calls;
    if (winmock::module_mode == winmock::ModuleMode::Growing) {
        *needed = bytes + static_cast<DWORD>(sizeof(HMODULE));
        return TRUE;
    }
    if (winmock::module_mode == winmock::ModuleMode::Misaligned) {
        *needed = bytes - 1;
        return TRUE;
    }
    *needed = static_cast<DWORD>(2 * sizeof(HMODULE));
    if (bytes >= *needed) {
        modules[0] = reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(0x111));
        modules[1] = reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(0x222));
    }
    return TRUE;
}
BOOL GetModuleInformation(HANDLE, HMODULE module, MODULEINFO* info, DWORD) noexcept {
    const auto id = reinterpret_cast<std::uintptr_t>(module);
    info->lpBaseOfDll = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x100000 + id * 0x10000));
    info->SizeOfImage = 0x2000;
    info->EntryPoint = nullptr;
    return TRUE;
}
DWORD GetModuleBaseNameW(HANDLE, HMODULE module, LPWSTR buffer, DWORD capacity) noexcept {
    const wchar_t* value = reinterpret_cast<std::uintptr_t>(module) == 0x111 ? L"alpha.dll" : L"beta.dll";
    const auto length = std::wcslen(value);
    if (capacity <= length) return 0;
    std::wmemcpy(buffer, value, length + 1);
    return static_cast<DWORD>(length);
}
DWORD GetModuleFileNameExW(HANDLE, HMODULE module, LPWSTR buffer, DWORD capacity) noexcept {
    const wchar_t* value = reinterpret_cast<std::uintptr_t>(module) == 0x111 ? L"C:\\alpha.dll" : L"C:\\beta.dll";
    const auto length = std::wcslen(value);
    if (capacity <= length) return 0;
    std::wmemcpy(buffer, value, length + 1);
    return static_cast<DWORD>(length);
}
HMODULE GetModuleHandleW(LPCWCH) noexcept { return reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(0x111)); }
HANDLE CreateToolhelp32Snapshot(DWORD, DWORD) noexcept {
    ++winmock::snapshot_calls;
    if (winmock::snapshot_error != NO_ERROR) {
        SetLastError(winmock::snapshot_error);
        return INVALID_HANDLE_VALUE;
    }
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x70));
}
BOOL Thread32First(HANDLE, THREADENTRY32* entry) noexcept {
    ++winmock::thread_first_calls;
    winmock::thread_next_calls = 0;
    if (winmock::thread_first_error != NO_ERROR) {
        SetLastError(winmock::thread_first_error);
        return FALSE;
    }
    entry->dwSize = sizeof(THREADENTRY32);
    entry->th32ThreadID = 77;
    entry->th32OwnerProcessID = GetCurrentProcessId();
    return TRUE;
}
BOOL Thread32Next(HANDLE, THREADENTRY32* entry) noexcept {
    ++winmock::thread_next_calls;
    if (winmock::thread_count > 1 && winmock::thread_next_calls == 1) {
        entry->dwSize = sizeof(THREADENTRY32);
        entry->th32ThreadID = 78;
        entry->th32OwnerProcessID = GetCurrentProcessId();
        return TRUE;
    }
    SetLastError(static_cast<DWORD>(winmock::thread_next_error));
    return FALSE;
}
HANDLE OpenThread(DWORD desired_access, BOOL, DWORD) noexcept {
    ++winmock::open_thread_calls;
    winmock::last_open_thread_access = desired_access;
    if (winmock::open_thread_error != NO_ERROR) {
        SetLastError(winmock::open_thread_error);
        return nullptr;
    }
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x71));
}
DWORD SuspendThread(HANDLE) noexcept {
    ++winmock::suspend_thread_calls;
    if (winmock::suspend_thread_error != NO_ERROR ||
        (winmock::suspend_thread_fail_on_call != 0 &&
         winmock::suspend_thread_calls == winmock::suspend_thread_fail_on_call)) {
        SetLastError(winmock::suspend_thread_error != NO_ERROR ? winmock::suspend_thread_error : ERROR_ACCESS_DENIED);
        return static_cast<DWORD>(-1);
    }
    return 0;
}
BOOL GetThreadContext(HANDLE, CONTEXT* context) noexcept {
    ++winmock::get_thread_context_calls;
    if (winmock::get_thread_context_error != NO_ERROR) { SetLastError(winmock::get_thread_context_error); return FALSE; }
    context->Eip = 0x5000;
    context->Rip = 0x5000;
    return TRUE;
}
DWORD ResumeThread(HANDLE) noexcept {
    ++winmock::resume_thread_calls;
    if (winmock::resume_thread_error != NO_ERROR) {
        SetLastError(winmock::resume_thread_error);
        return static_cast<DWORD>(-1);
    }
    return 1;
}
HANDLE CreateMutexW(void*, BOOL, LPCWCH) noexcept { return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x90)); }
DWORD WaitForSingleObject(HANDLE, DWORD) noexcept { return winmock::wait_for_single_object_result; }
BOOL ReleaseMutex(HANDLE) noexcept { return TRUE; }

LONG DetourTransactionBegin() noexcept { return NO_ERROR; }
LONG DetourTransactionAbort() noexcept { ++winmock::detour_abort_calls; return NO_ERROR; }
LONG DetourTransactionCommit() noexcept { return NO_ERROR; }
LONG DetourUpdateThread(HANDLE) noexcept { return winmock::detour_update_error; }
LONG DetourAttach(void**, void*) noexcept { ++winmock::detour_attach_calls; return winmock::detour_attach_error; }
LONG DetourDetach(void**, void*) noexcept { ++winmock::detour_detach_calls; return winmock::detour_detach_error; }
