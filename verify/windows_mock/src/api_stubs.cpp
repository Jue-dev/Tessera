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

std::array<MemoryApiCallRecord, 32> memory_api_call_log{};
std::array<NativeApiCallRecord, 64> native_api_call_log{};
int native_api_call_count = 0;
std::array<int, static_cast<std::size_t>(NativeApi::Count)> native_api_occurrence_counts{};
NativeApi fail_native_api = NativeApi::OpenProcess;
int fail_native_api_on_call = 0;
DWORD fail_native_api_error = ERROR_ACCESS_DENIED;
bool record_native_api_call(NativeApi call, HANDLE handle, std::uintptr_t a1,
                            std::uintptr_t a2, std::uintptr_t a3) noexcept {
    const auto api_index = static_cast<std::size_t>(call);
    const int occurrence = native_api_occurrence_counts[api_index]++;
    if (native_api_call_count < static_cast<int>(native_api_call_log.size()))
        native_api_call_log[static_cast<std::size_t>(native_api_call_count)] = {
            call, reinterpret_cast<std::uintptr_t>(handle), a1, a2, a3};
    ++native_api_call_count;
    return fail_native_api_on_call > 0 && fail_native_api == call &&
           occurrence + 1 == fail_native_api_on_call;
}
int memory_api_call_count = 0;

void record_memory_api_call(MemoryApiCall call, const void* address,
                            std::size_t size, DWORD protection = 0) noexcept {
    if (memory_api_call_count < static_cast<int>(memory_api_call_log.size())) {
        memory_api_call_log[static_cast<std::size_t>(memory_api_call_count++)] = {
            call, reinterpret_cast<std::uintptr_t>(address), size, protection};
    }
}

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
int close_handle_fail_on_call = 0;
DWORD close_handle_error = ERROR_ACCESS_DENIED;
int thread_count = 1;
int snapshot_thread_count = 1;
bool create_thread_during_suspend = false;
int create_threads_during_suspend_count = 0;
int create_threads_during_enumeration_count = 0;
int create_threads_during_context_count = 0;
int thread_next_calls = 0;
int suspend_thread_fail_on_call = 0;
DWORD suspend_thread_error = NO_ERROR;
DWORD get_thread_context_error = NO_ERROR;
int suspend_thread_calls = 0;
int get_thread_context_calls = 0;
int resume_thread_calls = 0;
DWORD resume_thread_error = NO_ERROR;
DWORD wait_for_single_object_result = WAIT_OBJECT_0;
DWORD release_mutex_error = NO_ERROR;
int release_mutex_calls = 0;
LONG detour_update_error = NO_ERROR;
LONG detour_attach_error = NO_ERROR;
LONG detour_detach_error = NO_ERROR;
LONG detour_commit_error = NO_ERROR;
int detour_attach_calls = 0;
int detour_detach_calls = 0;
int detour_abort_calls = 0;
std::array<std::byte, 64> process_memory{};
DWORD process_memory_protect = PAGE_EXECUTE_READ;
std::size_t max_read_chunk = static_cast<std::size_t>(-1);
int write_process_memory_calls = 0;
int write_process_memory_fail_on_call = 0;
int write_process_memory_fail_on_call_2 = 0;
DWORD write_process_memory_error = ERROR_ACCESS_DENIED;
std::size_t write_process_memory_partial_bytes = 0;
int virtual_protect_calls = 0;
int virtual_protect_fail_on_call = 0;
DWORD virtual_protect_error = ERROR_ACCESS_DENIED;
int flush_instruction_cache_calls = 0;
int flush_instruction_cache_fail_on_call = 0;
DWORD flush_instruction_cache_error = ERROR_ACCESS_DENIED;
USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
USHORT native_machine = IMAGE_FILE_MACHINE_AMD64;

void reset() noexcept {
    memory_api_call_log.fill({});
    memory_api_call_count = 0;
    native_api_call_log.fill({});
    native_api_call_count = 0;
    native_api_occurrence_counts.fill(0);
    fail_native_api = NativeApi::OpenProcess;
    fail_native_api_on_call = 0;
    fail_native_api_error = ERROR_ACCESS_DENIED;
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
    close_handle_fail_on_call = 0;
    close_handle_error = ERROR_ACCESS_DENIED;
    thread_count = 1;
    snapshot_thread_count = 1;
    create_thread_during_suspend = false;
    create_threads_during_suspend_count = 0;
    create_threads_during_enumeration_count = 0;
    create_threads_during_context_count = 0;
    thread_next_calls = 0;
    suspend_thread_fail_on_call = 0;
    suspend_thread_error = NO_ERROR;
    get_thread_context_error = NO_ERROR;
    suspend_thread_calls = 0;
    get_thread_context_calls = 0;
    resume_thread_calls = 0;
    resume_thread_error = NO_ERROR;
    wait_for_single_object_result = WAIT_OBJECT_0;
    release_mutex_error = NO_ERROR;
    release_mutex_calls = 0;
    detour_update_error = NO_ERROR;
    detour_attach_error = NO_ERROR;
    detour_detach_error = NO_ERROR;
    detour_commit_error = NO_ERROR;
    detour_attach_calls = 0;
    detour_detach_calls = 0;
    detour_abort_calls = 0;
    for (std::size_t i = 0; i < process_memory.size(); ++i) {
        process_memory[i] = static_cast<std::byte>(i);
    }
    process_memory_protect = PAGE_EXECUTE_READ;
    max_read_chunk = static_cast<std::size_t>(-1);
    write_process_memory_calls = 0;
    write_process_memory_fail_on_call = 0;
    write_process_memory_fail_on_call_2 = 0;
    write_process_memory_error = ERROR_ACCESS_DENIED;
    write_process_memory_partial_bytes = 0;
    virtual_protect_calls = 0;
    virtual_protect_fail_on_call = 0;
    virtual_protect_error = ERROR_ACCESS_DENIED;
    flush_instruction_cache_calls = 0;
    flush_instruction_cache_fail_on_call = 0;
    flush_instruction_cache_error = ERROR_ACCESS_DENIED;
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
BOOL CloseHandle(HANDLE) noexcept {
    ++winmock::close_handle_calls;
    if (winmock::close_handle_fail_on_call != 0 &&
        winmock::close_handle_calls == winmock::close_handle_fail_on_call) {
        SetLastError(winmock::close_handle_error);
        return FALSE;
    }
    return TRUE;
}
BOOL IsWow64Process2(HANDLE handle, USHORT* process_machine, USHORT* native_machine) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::IsWow64Process2, handle,
            reinterpret_cast<std::uintptr_t>(process_machine), reinterpret_cast<std::uintptr_t>(native_machine))) {
        SetLastError(winmock::fail_native_api_error); return FALSE;
    }
    *process_machine = winmock::process_machine;
    *native_machine = winmock::native_machine;
    return TRUE;
}
void GetNativeSystemInfo(SYSTEM_INFO* info) noexcept {
    (void)winmock::record_native_api_call(winmock::NativeApi::GetNativeSystemInfo, nullptr,
            reinterpret_cast<std::uintptr_t>(info));
    info->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    info->lpMaximumApplicationAddress = reinterpret_cast<void*>(0x7fffffffffffULL);
}
HANDLE OpenProcess(DWORD access, BOOL inherit, DWORD pid) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::OpenProcess, nullptr, access, inherit, pid)) {
        SetLastError(winmock::fail_native_api_error); return nullptr;
    }
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x44));
}
BOOL GetExitCodeProcess(HANDLE handle, DWORD* code) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::GetExitCodeProcess, handle, reinterpret_cast<std::uintptr_t>(code))) {
        SetLastError(winmock::fail_native_api_error); return FALSE;
    }
    *code = STILL_ACTIVE; return TRUE;
}
DWORD GetProcessId(HANDLE handle) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::GetProcessId, handle)) {
        SetLastError(winmock::fail_native_api_error); return 0;
    }
    return 42;
}
BOOL ReadProcessMemory(HANDLE handle, LPCVOID address, LPVOID buffer, SIZE_T requested, SIZE_T* transferred) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::ReadProcessMemory, handle,
            reinterpret_cast<std::uintptr_t>(address), requested, reinterpret_cast<std::uintptr_t>(buffer))) {
        *transferred = 0; SetLastError(winmock::fail_native_api_error); return FALSE;
    }
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
    ++winmock::write_process_memory_calls;
    winmock::record_memory_api_call(winmock::MemoryApiCall::WriteProcessMemory, address, requested);
    constexpr std::uintptr_t base = 0x1000;
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (value < base || value - base >= winmock::process_memory.size()) {
        *transferred = 0;
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const std::size_t offset = static_cast<std::size_t>(value - base);
    const std::size_t available = winmock::process_memory.size() - offset;
    const bool primary_failure =
        winmock::write_process_memory_fail_on_call != 0 &&
        winmock::write_process_memory_calls == winmock::write_process_memory_fail_on_call;
    const bool secondary_failure =
        winmock::write_process_memory_fail_on_call_2 != 0 &&
        winmock::write_process_memory_calls == winmock::write_process_memory_fail_on_call_2;
    if (primary_failure || secondary_failure) {
        const std::size_t partial = primary_failure
            ? (std::min)({requested, available, winmock::write_process_memory_partial_bytes})
            : 0u;
        if (partial != 0) {
            std::memcpy(winmock::process_memory.data() + offset, buffer, partial);
        }
        *transferred = partial;
        SetLastError(winmock::write_process_memory_error);
        return FALSE;
    }
    const std::size_t count = (std::min)(requested, available);
    std::memcpy(winmock::process_memory.data() + offset, buffer, count);
    *transferred = count;
    if (count != requested) { SetLastError(ERROR_PARTIAL_COPY); return FALSE; }
    return TRUE;
}
SIZE_T VirtualQueryEx(HANDLE handle, LPCVOID address, MEMORY_BASIC_INFORMATION* mbi, SIZE_T size) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::VirtualQueryEx, handle,
            reinterpret_cast<std::uintptr_t>(address), reinterpret_cast<std::uintptr_t>(mbi), size)) {
        SetLastError(winmock::fail_native_api_error); return 0;
    }
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
BOOL VirtualProtectEx(HANDLE, LPVOID address, SIZE_T size, DWORD new_protection, DWORD* old_protection) noexcept {
    ++winmock::virtual_protect_calls;
    winmock::record_memory_api_call(winmock::MemoryApiCall::VirtualProtectEx, address, size, new_protection);
    if (winmock::virtual_protect_fail_on_call != 0 &&
        winmock::virtual_protect_calls == winmock::virtual_protect_fail_on_call) {
        SetLastError(winmock::virtual_protect_error);
        return FALSE;
    }
    *old_protection = winmock::process_memory_protect;
    winmock::process_memory_protect = new_protection;
    return TRUE;
}
BOOL FlushInstructionCache(HANDLE, LPCVOID address, SIZE_T size) noexcept {
    ++winmock::flush_instruction_cache_calls;
    winmock::record_memory_api_call(winmock::MemoryApiCall::FlushInstructionCache, address, size);
    if (winmock::flush_instruction_cache_fail_on_call != 0 &&
        winmock::flush_instruction_cache_calls == winmock::flush_instruction_cache_fail_on_call) {
        SetLastError(winmock::flush_instruction_cache_error);
        return FALSE;
    }
    return TRUE;
}
int CompareStringOrdinal(LPCWCH a, int alen, LPCWCH b, int blen, BOOL ignore_case) noexcept {
    if (alen != blen) return 0;
    for (int i = 0; i < alen; ++i) {
        wchar_t ac = a[i], bc = b[i];
        if (ignore_case) { ac = static_cast<wchar_t>(std::towlower(ac)); bc = static_cast<wchar_t>(std::towlower(bc)); }
        if (ac != bc) return 0;
    }
    return CSTR_EQUAL;
}
BOOL EnumProcessModulesEx(HANDLE handle, HMODULE* modules, DWORD bytes, DWORD* needed, DWORD flags) noexcept {
    ++winmock::module_calls;
    if (winmock::record_native_api_call(winmock::NativeApi::EnumProcessModulesEx, handle,
            reinterpret_cast<std::uintptr_t>(modules), bytes, flags)) {
        SetLastError(winmock::fail_native_api_error); return FALSE;
    }
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
BOOL GetModuleInformation(HANDLE handle, HMODULE module, MODULEINFO* info, DWORD size) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::GetModuleInformation, handle,
            reinterpret_cast<std::uintptr_t>(module), reinterpret_cast<std::uintptr_t>(info), size)) {
        SetLastError(winmock::fail_native_api_error); return FALSE;
    }
    const auto id = reinterpret_cast<std::uintptr_t>(module);
    info->lpBaseOfDll = reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x100000 + id * 0x10000));
    info->SizeOfImage = 0x2000;
    info->EntryPoint = nullptr;
    return TRUE;
}
DWORD GetModuleBaseNameW(HANDLE handle, HMODULE module, LPWSTR buffer, DWORD capacity) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::GetModuleBaseNameW, handle,
            reinterpret_cast<std::uintptr_t>(module), reinterpret_cast<std::uintptr_t>(buffer), capacity)) {
        SetLastError(winmock::fail_native_api_error); return 0;
    }
    const wchar_t* value = reinterpret_cast<std::uintptr_t>(module) == 0x111 ? L"alpha.dll" : L"beta.dll";
    const auto length = std::wcslen(value);
    if (capacity <= length) return 0;
    std::wmemcpy(buffer, value, length + 1);
    return static_cast<DWORD>(length);
}
DWORD GetModuleFileNameExW(HANDLE handle, HMODULE module, LPWSTR buffer, DWORD capacity) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::GetModuleFileNameExW, handle,
            reinterpret_cast<std::uintptr_t>(module), reinterpret_cast<std::uintptr_t>(buffer), capacity)) {
        SetLastError(winmock::fail_native_api_error); return 0;
    }
    const wchar_t* value = reinterpret_cast<std::uintptr_t>(module) == 0x111 ? L"C:\\alpha.dll" : L"C:\\beta.dll";
    const auto length = std::wcslen(value);
    if (capacity <= length) return 0;
    std::wmemcpy(buffer, value, length + 1);
    return static_cast<DWORD>(length);
}
HMODULE GetModuleHandleW(LPCWCH name) noexcept {
    if (winmock::record_native_api_call(winmock::NativeApi::GetModuleHandleW, nullptr,
            reinterpret_cast<std::uintptr_t>(name))) {
        SetLastError(winmock::fail_native_api_error); return nullptr;
    }
    return reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(0x111));
}
HANDLE CreateToolhelp32Snapshot(DWORD, DWORD) noexcept {
    ++winmock::snapshot_calls;
    // Toolhelp snapshots capture a finite enumeration view at creation time.
    winmock::snapshot_thread_count = winmock::thread_count;
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
    if (winmock::create_threads_during_enumeration_count > 0) {
        ++winmock::thread_count;
        --winmock::create_threads_during_enumeration_count;
    }
    if (winmock::thread_next_calls < winmock::snapshot_thread_count) {
        entry->dwSize = sizeof(THREADENTRY32);
        entry->th32ThreadID = 77u + static_cast<DWORD>(winmock::thread_next_calls);
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
    if (winmock::create_thread_during_suspend) {
        // Model a host creating a new thread after the snapshot was captured.
        ++winmock::thread_count;
        winmock::create_thread_during_suspend = false;
    }
    if (winmock::create_threads_during_suspend_count > 0) {
        ++winmock::thread_count;
        --winmock::create_threads_during_suspend_count;
    }
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
    if (winmock::create_threads_during_context_count > 0) {
        ++winmock::thread_count;
        --winmock::create_threads_during_context_count;
    }
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
BOOL ReleaseMutex(HANDLE) noexcept {
    ++winmock::release_mutex_calls;
    if (winmock::release_mutex_error != NO_ERROR) {
        SetLastError(winmock::release_mutex_error);
        return FALSE;
    }
    return TRUE;
}

LONG DetourTransactionBegin() noexcept { return NO_ERROR; }
LONG DetourTransactionAbort() noexcept { ++winmock::detour_abort_calls; return NO_ERROR; }
LONG DetourTransactionCommit() noexcept { return winmock::detour_commit_error; }
LONG DetourUpdateThread(HANDLE) noexcept { return winmock::detour_update_error; }
LONG DetourAttach(void**, void*) noexcept { ++winmock::detour_attach_calls; return winmock::detour_attach_error; }
LONG DetourDetach(void**, void*) noexcept { ++winmock::detour_detach_calls; return winmock::detour_detach_error; }

DWORD FormatMessageW(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list*) noexcept {
    return 0;
}
HLOCAL LocalFree(HLOCAL memory) noexcept {
    return memory;
}
int WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, BOOL*) noexcept {
    return 0;
}

HANDLE GetStdHandle(DWORD) noexcept { return nullptr; }
BOOL WriteFile(HANDLE, LPCVOID, DWORD count, DWORD* written, void*) noexcept {
    if (written != nullptr) { *written = count; }
    return TRUE;
}
void OutputDebugStringW(LPCWSTR) noexcept {}
HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE) noexcept {
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_HANDLE_VALUE;
}
BOOL SetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER*, DWORD) noexcept { return TRUE; }
BOOL FlushFileBuffers(HANDLE) noexcept { return TRUE; }
