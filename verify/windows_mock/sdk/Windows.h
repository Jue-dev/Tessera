#pragma once
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <limits>
using BYTE = unsigned char;
using WORD = std::uint16_t;
using USHORT = std::uint16_t;
using DWORD = std::uint32_t;
using LONG = std::int32_t;
using BOOL = int;
using SIZE_T = std::size_t;
using HANDLE = void*;
using HMODULE = void*;
using LPVOID = void*;
using LPCVOID = const void*;
using LPCWCH = const wchar_t*;
using LPWSTR = wchar_t*;
using WCHAR = wchar_t;
struct SYSTEM_INFO { WORD wProcessorArchitecture; WORD wReserved; DWORD dwPageSize; LPVOID lpMinimumApplicationAddress; LPVOID lpMaximumApplicationAddress; std::uintptr_t dwActiveProcessorMask; DWORD dwNumberOfProcessors; DWORD dwProcessorType; DWORD dwAllocationGranularity; WORD wProcessorLevel; WORD wProcessorRevision; };
struct MEMORY_BASIC_INFORMATION { LPVOID BaseAddress; LPVOID AllocationBase; DWORD AllocationProtect; WORD PartitionId; SIZE_T RegionSize; DWORD State; DWORD Protect; DWORD Type; };
struct MODULEINFO { LPVOID lpBaseOfDll; DWORD SizeOfImage; LPVOID EntryPoint; };
struct THREADENTRY32 { DWORD dwSize; DWORD cntUsage; DWORD th32ThreadID; DWORD th32OwnerProcessID; LONG tpBasePri; LONG tpDeltaPri; DWORD dwFlags; };
#define TRUE 1
#define MAX_PATH 260
#define FALSE 0
#define INVALID_HANDLE_VALUE reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1))
#define NO_ERROR 0u
#define STILL_ACTIVE 259u
#define INFINITE 0xFFFFFFFFu
#define WAIT_OBJECT_0 0u
#define WAIT_ABANDONED 0x80u
#define WAIT_FAILED 0xFFFFFFFFu
#define CSTR_EQUAL 2
#define PROCESSOR_ARCHITECTURE_INTEL 0
#define PROCESSOR_ARCHITECTURE_AMD64 9
#define IMAGE_FILE_MACHINE_UNKNOWN 0
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#define PROCESS_QUERY_INFORMATION 0x0400u
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define PROCESS_VM_READ 0x0010u
#define PROCESS_VM_WRITE 0x0020u
#define PROCESS_VM_OPERATION 0x0008u
#define SYNCHRONIZE 0x00100000u
#define THREAD_SUSPEND_RESUME 0x0002u
#define THREAD_GET_CONTEXT 0x0008u
#define THREAD_SET_CONTEXT 0x0010u
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_PRIVILEGE_NOT_HELD 1314u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOT_FOUND 1168u
#define ERROR_INVALID_OPERATION 4317u
#define ERROR_NO_MORE_FILES 18u
#define ERROR_PARTIAL_COPY 299u
#define MEM_COMMIT 0x1000u
#define MEM_RESERVE 0x2000u
#define MEM_FREE 0x10000u
#define MEM_IMAGE 0x1000000u
#define MEM_MAPPED 0x40000u
#define MEM_PRIVATE 0x20000u
#define PAGE_NOACCESS 0x01u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
#define PAGE_WRITECOPY 0x08u
#define PAGE_EXECUTE 0x10u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_EXECUTE_WRITECOPY 0x80u
#define PAGE_GUARD 0x100u
#define PAGE_NOCACHE 0x200u
#define PAGE_WRITECOMBINE 0x400u
#define TH32CS_SNAPTHREAD 0x00000004u
#define FIELD_OFFSET(type, field) static_cast<LONG>(offsetof(type, field))
DWORD GetLastError() noexcept;
void SetLastError(DWORD) noexcept;
HANDLE GetCurrentProcess() noexcept;
DWORD GetCurrentProcessId() noexcept;
HANDLE GetCurrentThread() noexcept;
DWORD GetCurrentThreadId() noexcept;
BOOL CloseHandle(HANDLE) noexcept;
BOOL IsWow64Process2(HANDLE, USHORT*, USHORT*) noexcept;
void GetNativeSystemInfo(SYSTEM_INFO*) noexcept;
HANDLE OpenProcess(DWORD, BOOL, DWORD) noexcept;
BOOL GetExitCodeProcess(HANDLE, DWORD*) noexcept;
DWORD GetProcessId(HANDLE) noexcept;
BOOL ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) noexcept;
BOOL WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) noexcept;
SIZE_T VirtualQueryEx(HANDLE, LPCVOID, MEMORY_BASIC_INFORMATION*, SIZE_T) noexcept;
BOOL VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD*) noexcept;
BOOL FlushInstructionCache(HANDLE, LPCVOID, SIZE_T) noexcept;
int CompareStringOrdinal(LPCWCH, int, LPCWCH, int, BOOL) noexcept;
BOOL EnumProcessModulesEx(HANDLE, HMODULE*, DWORD, DWORD*, DWORD) noexcept;
BOOL GetModuleInformation(HANDLE, HMODULE, MODULEINFO*, DWORD) noexcept;
DWORD GetModuleBaseNameW(HANDLE, HMODULE, LPWSTR, DWORD) noexcept;
DWORD GetModuleFileNameExW(HANDLE, HMODULE, LPWSTR, DWORD) noexcept;
HMODULE GetModuleHandleW(LPCWCH) noexcept;
HANDLE CreateToolhelp32Snapshot(DWORD, DWORD) noexcept;
BOOL Thread32First(HANDLE, THREADENTRY32*) noexcept;
BOOL Thread32Next(HANDLE, THREADENTRY32*) noexcept;
HANDLE OpenThread(DWORD, BOOL, DWORD) noexcept;
HANDLE CreateMutexW(void*, BOOL, LPCWCH) noexcept;
DWORD WaitForSingleObject(HANDLE, DWORD) noexcept;
BOOL ReleaseMutex(HANDLE) noexcept;
