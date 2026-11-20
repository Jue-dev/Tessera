#include <Windows.h>
#include <Psapi.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string_view>
#if defined(__linux__)
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "tessera/module/module.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/memory_writer.hpp"
#include "tessera/platform/windows/native.hpp"
#include "platform/windows/thread_backend.hpp"
#include "hook/backends/native_thread_suspension.hpp"
#include "tessera/hook/hook.hpp"
#include "api_stubs.hpp"

namespace {
int failures = 0;
void check(bool condition, const char* name) {
    if (condition) std::printf("PASS %s\n", name);
    else { std::printf("FAIL %s\n", name); ++failures; }
}
}

int main() {
    using namespace tessera;
    using namespace tessera::platform::windows;
    auto process = from_native_handle(reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x44)), Ownership::Borrowed);
    check(process.has_value(), "from_native_handle builds a mock x64 Process");
    if (!process) return 2;

    // Process-open contract: required query-limited access is always requested,
    // while the caller's requested VM rights and PID are preserved exactly.
    winmock::reset();
    auto opened_process = Process::open(ProcessId{123}, ProcessAccess::Read);
    constexpr DWORD expected_process_access = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
    check(opened_process && winmock::native_api_call_count >= 4 &&
              winmock::native_api_call_log[0].call == winmock::NativeApi::OpenProcess &&
              winmock::native_api_call_log[0].argument1 == expected_process_access &&
              winmock::native_api_call_log[0].argument2 == FALSE &&
              winmock::native_api_call_log[0].argument3 == 123 &&
              winmock::native_api_call_log[1].call == winmock::NativeApi::GetProcessId &&
              winmock::native_api_call_log[1].handle == 0x44 &&
              winmock::native_api_call_log[2].call == winmock::NativeApi::IsWow64Process2 &&
              winmock::native_api_call_log[2].handle == 0x44,
          "Process::open records exact PID/access mask and native-handle query ordering");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::OpenProcess;
    winmock::fail_native_api_on_call = 1;
    auto open_api_failure = Process::open(ProcessId{123}, ProcessAccess::Read);
    check(!open_api_failure && open_api_failure.error().operation == "OpenProcess" &&
              open_api_failure.error().native == ERROR_ACCESS_DENIED,
          "OpenProcess indexed failure preserves the Win32 error and fails closed");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetProcessId;
    winmock::fail_native_api_on_call = 1;
    auto pid_api_failure = from_native_handle(reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x45)),
                                              Ownership::Owned);
    check(!pid_api_failure && pid_api_failure.error().operation == "GetProcessId" &&
              pid_api_failure.error().native == ERROR_ACCESS_DENIED && winmock::close_handle_calls == 1,
          "GetProcessId indexed failure closes the owned native handle");

    winmock::reset();
    winmock::process_machine = IMAGE_FILE_MACHINE_I386;
    auto wow64_process = from_native_handle(reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x45)),
                                            Ownership::Borrowed);
    check(wow64_process && wow64_process->info().architecture == Architecture::X86 &&
              wow64_process->info().pointer_size == 4,
          "Process backend identifies a 32-bit target on an x64 host");
    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::IsWow64Process2;
    winmock::fail_native_api_on_call = 1;
    auto architecture_api_failure = from_native_handle(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x46)), Ownership::Owned);
    check(!architecture_api_failure &&
              architecture_api_failure.error().operation == "IsWow64Process2" &&
              architecture_api_failure.error().native == ERROR_ACCESS_DENIED &&
              winmock::close_handle_calls == 1,
          "IsWow64Process2 indexed failure closes owned handle and preserves native error");

    winmock::reset();
    winmock::native_machine = IMAGE_FILE_MACHINE_ARM64;
    auto unsupported_process = from_native_handle(reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x46)),
                                                  Ownership::Borrowed);
    check(!unsupported_process && unsupported_process.error().code == ErrorCode::UnsupportedArchitecture,
          "Process backend rejects unsupported native architectures");

    winmock::reset();
    auto alive_failure_process = from_native_handle(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x47)), Ownership::Borrowed);
    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetExitCodeProcess;
    winmock::fail_native_api_on_call = 1;
    auto alive_api_failure = alive_failure_process->is_alive();
    check(!alive_api_failure && alive_api_failure.error().operation == "GetExitCodeProcess" &&
              alive_api_failure.error().native == ERROR_ACCESS_DENIED,
          "GetExitCodeProcess indexed failure is surfaced by Process::is_alive");

    winmock::reset();
    MemoryReader memory_reader{*process};
    auto read = memory_reader.read_bytes(Address{0x1000}, 4);
    check(read && read->size() == 4 && (*read)[0] == std::byte{0} && (*read)[3] == std::byte{3},
          "Windows memory backend reads remote bytes");
    auto query = memory_reader.query(Address{0x1001});
    check(query && query->state == MemoryState::Committed && query->protection == MemoryProtection::ExecuteRead &&
              query->type == MemoryType::Private,
          "Windows memory backend maps VirtualQueryEx metadata");
    auto executable = memory_reader.is_executable(AddressRange{Address{0x1000}, 4});
    check(executable && *executable, "Windows memory backend recognizes executable protection");
    MemoryWriter memory_writer{*process};
    const std::array<std::byte, 3> replacement_bytes{std::byte{0xA1}, std::byte{0xB2}, std::byte{0xC3}};
    auto write = memory_writer.write(Address{0x1004}, replacement_bytes);
    check(write && winmock::process_memory[4] == std::byte{0xA1} &&
              winmock::process_memory[6] == std::byte{0xC3} &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ &&
              winmock::flush_instruction_cache_calls == 1,
          "Windows memory backend writes bytes, restores protection, and flushes instruction cache");
    const auto& memory_calls = winmock::memory_api_call_log;
    const bool memory_api_order_and_arguments =
        winmock::memory_api_call_count == 4 &&
        memory_calls[0].call == winmock::MemoryApiCall::VirtualProtectEx &&
        memory_calls[0].address == 0x1004 &&
        memory_calls[0].size == replacement_bytes.size() &&
        memory_calls[0].protection == PAGE_EXECUTE_READWRITE &&
        memory_calls[1].call == winmock::MemoryApiCall::WriteProcessMemory &&
        memory_calls[1].address == 0x1004 &&
        memory_calls[1].size == replacement_bytes.size() &&
        memory_calls[2].call == winmock::MemoryApiCall::VirtualProtectEx &&
        memory_calls[2].address == 0x1004 &&
        memory_calls[2].size == replacement_bytes.size() &&
        memory_calls[2].protection == PAGE_EXECUTE_READ &&
        memory_calls[3].call == winmock::MemoryApiCall::FlushInstructionCache &&
        memory_calls[3].address == 0x1004 &&
        memory_calls[3].size == replacement_bytes.size();
    check(memory_api_order_and_arguments,
          "MemoryWriter preserves protection/write/restore/flush order and exact API ranges");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::ReadProcessMemory;
    winmock::fail_native_api_on_call = 1;
    auto read_api_failure = memory_reader.read_bytes(Address{0x1000}, 4);
    check(!read_api_failure && read_api_failure.error().operation == "ReadProcessMemory" &&
              read_api_failure.error().native == ERROR_ACCESS_DENIED &&
              winmock::native_api_call_log[0].argument1 == 0x1000 &&
              winmock::native_api_call_log[0].argument2 == 4,
          "ReadProcessMemory indexed failure preserves address, size, and native error");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::VirtualQueryEx;
    winmock::fail_native_api_on_call = 1;
    auto query_api_failure = memory_reader.query(Address{0x1001});
    check(!query_api_failure && query_api_failure.error().operation == "VirtualQueryEx" &&
              query_api_failure.error().native == ERROR_ACCESS_DENIED &&
              winmock::native_api_call_log[0].argument1 == 0x1001 &&
              winmock::native_api_call_log[0].argument3 == sizeof(MEMORY_BASIC_INFORMATION),
          "VirtualQueryEx indexed failure preserves address, structure size, and native error");

    winmock::reset();
    winmock::max_read_chunk = 2;
    std::array<std::byte, 4> partial_buffer{};
    auto partial = memory_reader.read_partial(Address{0x1000}, partial_buffer);
    check(partial && *partial == 2, "Windows memory backend reports partial ReadProcessMemory transfer");

    // Deterministic Windows memory API failures exercise MemoryWriter's
    // protection, rollback, and instruction-cache recovery branches.
    winmock::reset();
    winmock::virtual_protect_fail_on_call = 1;
    auto initial_protection_failure =
        memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    check(initial_protection_failure && initial_protection_failure->write_error &&
              initial_protection_failure->write_error->operation == "VirtualProtectEx" &&
              initial_protection_failure->write_error->code == ErrorCode::ProtectionFailed &&
              initial_protection_failure->bytes_written == 0 &&
              winmock::write_process_memory_calls == 0 &&
              winmock::process_memory[4] == std::byte{4} &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "initial VirtualProtectEx failure prevents writes and preserves original bytes");

    winmock::reset();
    winmock::write_process_memory_fail_on_call = 1;
    auto write_failure = memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    check(write_failure && write_failure->write_error &&
              write_failure->write_error->operation == "WriteProcessMemory" &&
              write_failure->write_error->code == ErrorCode::AccessDenied &&
              write_failure->bytes_written == 0 && !write_failure->rollback_error &&
              winmock::process_memory[4] == std::byte{4} &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "zero-byte WriteProcessMemory failure restores page protection without rollback");

    winmock::reset();
    winmock::write_process_memory_fail_on_call = 1;
    winmock::write_process_memory_partial_bytes = 1;
    auto partial_write = memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    check(partial_write && partial_write->write_error &&
              partial_write->write_error->code == ErrorCode::PartialTransfer &&
              partial_write->rolled_back && !partial_write->rollback_error &&
              winmock::process_memory[4] == std::byte{4} &&
              winmock::process_memory[5] == std::byte{5} &&
              winmock::process_memory[6] == std::byte{6} &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "partial WriteProcessMemory transfer is rolled back and protection restored");

    winmock::reset();
    winmock::write_process_memory_fail_on_call = 1;
    winmock::write_process_memory_fail_on_call_2 = 2;
    winmock::write_process_memory_partial_bytes = 1;
    auto rollback_failure = memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    check(rollback_failure && rollback_failure->write_error &&
              rollback_failure->rollback_error && !rollback_failure->rolled_back &&
              winmock::process_memory[4] == std::byte{0xA1} &&
              winmock::process_memory[5] == std::byte{5} &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "rollback WriteProcessMemory failure is surfaced without claiming rollback success");

    winmock::reset();
    winmock::virtual_protect_fail_on_call = 2;
    auto restore_report = memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    const bool restore_ticket_created =
        restore_report && restore_report->pending_protection_restores.size() == 1 &&
        restore_report->protection_restore_warning.has_value() &&
        winmock::process_memory_protect == PAGE_EXECUTE_READWRITE;
    winmock::virtual_protect_fail_on_call = 3;
    auto restore_retry_failure = restore_report
        ? memory_writer.restore_pending_protections(*restore_report)
        : Status{std::unexpected(make_error(ErrorCode::IoError, "test"))};
    const bool restore_ticket_retained =
        restore_report && !restore_retry_failure &&
        restore_report->pending_protection_restores.size() == 1;
    winmock::virtual_protect_fail_on_call = 0;
    auto restore_retry_success = restore_report
        ? memory_writer.restore_pending_protections(*restore_report)
        : Status{std::unexpected(make_error(ErrorCode::IoError, "test"))};
    check(restore_ticket_created && restore_ticket_retained && restore_retry_success &&
              restore_report->pending_protection_restores.empty() &&
              !restore_report->protection_restore_warning &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "protection restoration ticket survives retry failure and clears after successful retry");

    // Exercise a compound failure: the write partially commits, rollback
    // fails, and page-protection restoration fails in the same transaction.
    // The report must preserve both primary/rollback diagnostics and retain
    // the exact protection ticket for an explicit later retry.
    winmock::reset();
    winmock::write_process_memory_fail_on_call = 1;
    winmock::write_process_memory_fail_on_call_2 = 2;
    winmock::write_process_memory_partial_bytes = 1;
    winmock::virtual_protect_fail_on_call = 2;
    auto compound_failure = memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    const bool compound_failure_reported =
        compound_failure && compound_failure->write_error &&
        compound_failure->write_error->code == ErrorCode::PartialTransfer &&
        compound_failure->rollback_error &&
        compound_failure->rollback_error->operation == "WriteProcessMemory" &&
        compound_failure->rollback_error->code == ErrorCode::AccessDenied &&
        compound_failure->protection_restore_warning &&
        compound_failure->protection_restore_warning->operation == "VirtualProtectEx" &&
        !compound_failure->succeeded() &&
        compound_failure->pending_protection_restores.size() == 1 &&
        winmock::process_memory[4] == std::byte{0xA1} &&
        winmock::process_memory_protect == PAGE_EXECUTE_READWRITE;
    winmock::virtual_protect_fail_on_call = 0;
    auto compound_restore = compound_failure
        ? memory_writer.restore_pending_protections(*compound_failure)
        : Status{std::unexpected(make_error(ErrorCode::IoError, "test"))};
    check(compound_failure_reported && compound_restore &&
              compound_failure->pending_protection_restores.empty() &&
              !compound_failure->protection_restore_warning &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "compound write, rollback, and protection failures preserve diagnostics and retry ownership");

    winmock::reset();
    winmock::flush_instruction_cache_fail_on_call = 1;
    auto flush_failure = memory_writer.write_with_report(Address{0x1004}, replacement_bytes);
    check(flush_failure && flush_failure->bytes_written == replacement_bytes.size() &&
              flush_failure->icache_flush_error &&
              flush_failure->icache_flush_error->operation == "FlushInstructionCache" &&
              flush_failure->icache_flush_error->code == ErrorCode::IoError &&
              winmock::process_memory_protect == PAGE_EXECUTE_READ,
          "FlushInstructionCache failure is surfaced after write and protection restoration");

    winmock::reset();
    auto modules = ModuleCatalog::snapshot(*process);
    check(modules.has_value() && modules->size() == 2, "stable ModuleCatalog snapshot returns both modules");
    if (modules && modules->size() == 2) {
        check(modules->at(0).size() == 0x2000 && modules->at(1).size() == 0x2000 &&
                  modules->at(0).base() != modules->at(1).base(),
              "ModuleCatalog returns distinct module image ranges");
    }
    const auto& module_api_log = winmock::native_api_call_log;
    check(winmock::native_api_call_count == 7 &&
              module_api_log[0].call == winmock::NativeApi::EnumProcessModulesEx &&
              module_api_log[0].handle == 0x44 &&
              module_api_log[0].argument2 == 256 * sizeof(HMODULE) &&
              module_api_log[0].argument3 == LIST_MODULES_ALL &&
              module_api_log[1].call == winmock::NativeApi::GetModuleInformation &&
              module_api_log[1].argument1 == 0x111 &&
              module_api_log[1].argument3 == sizeof(MODULEINFO) &&
              module_api_log[2].call == winmock::NativeApi::GetModuleBaseNameW &&
              module_api_log[2].argument1 == 0x111 &&
              module_api_log[2].argument3 == MAX_PATH &&
              module_api_log[3].call == winmock::NativeApi::GetModuleFileNameExW &&
              module_api_log[3].argument1 == 0x111 &&
              module_api_log[3].argument3 == MAX_PATH * 2 &&
              module_api_log[4].call == winmock::NativeApi::GetModuleInformation &&
              module_api_log[4].argument1 == 0x222,
          "module enumeration records buffer bytes, flags, handles, and metadata/name/path query order");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::EnumProcessModulesEx;
    winmock::fail_native_api_on_call = 1;
    auto enum_api_failure = ModuleCatalog::snapshot(*process);
    check(!enum_api_failure && enum_api_failure.error().operation == "EnumProcessModulesEx" &&
              enum_api_failure.error().native == ERROR_ACCESS_DENIED && winmock::module_calls == 1,
          "EnumProcessModulesEx indexed failure reports native error without retrying");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetModuleInformation;
    winmock::fail_native_api_on_call = 1;
    auto info_api_failure = ModuleCatalog::snapshot(*process);
    std::printf("DEBUG info snapshot=%d size=%zu calls=%d fail=%d local=%d\\n",
                static_cast<int>(info_api_failure.has_value()),
                info_api_failure ? info_api_failure->size() : 0u,
                winmock::native_api_call_count, winmock::fail_native_api_on_call,
                static_cast<int>(process->is_local()));
    check(info_api_failure && info_api_failure->size() == 1 &&
              info_api_failure->front().name() == u"beta.dll" &&
              winmock::native_api_call_log[1].call == winmock::NativeApi::GetModuleInformation,
          "GetModuleInformation failure skips only the affected module");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetModuleBaseNameW;
    winmock::fail_native_api_on_call = 1;
    auto base_name_api_failure = ModuleCatalog::snapshot(*process);
    std::printf("DEBUG basename snapshot=%d size=%zu calls=%d\\n",
                static_cast<int>(base_name_api_failure.has_value()),
                base_name_api_failure ? base_name_api_failure->size() : 0u,
                winmock::native_api_call_count);
    check(base_name_api_failure && base_name_api_failure->size() == 1 &&
              base_name_api_failure->front().name() == u"beta.dll",
          "GetModuleBaseNameW failure skips only the affected module");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetModuleFileNameExW;
    winmock::fail_native_api_on_call = 1;
    auto path_api_failure = ModuleCatalog::snapshot(*process);
    std::printf("DEBUG path snapshot=%d size=%zu calls=%d\\n",
                static_cast<int>(path_api_failure.has_value()),
                path_api_failure ? path_api_failure->size() : 0u,
                winmock::native_api_call_count);
    check(path_api_failure && path_api_failure->size() == 2 &&
              path_api_failure->front().name() == u"alpha.dll" &&
              path_api_failure->front().full_path().empty(),
          "GetModuleFileNameExW failure leaves optional path empty without fabricating path data");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetModuleHandleW;
    winmock::fail_native_api_on_call = 1;
    auto main_handle_api_failure = ModuleCatalog::main_module(*process);
    check(!main_handle_api_failure && main_handle_api_failure.error().operation == "GetModuleHandleW" &&
              main_handle_api_failure.error().native == ERROR_ACCESS_DENIED,
          "GetModuleHandleW indexed failure is surfaced as a missing main module");

    winmock::reset();
    auto local_main_module = ModuleCatalog::main_module(*process);
    check(local_main_module && local_main_module->name() == u"alpha.dll" &&
              winmock::native_api_call_count == 4 &&
              winmock::native_api_call_log[0].call == winmock::NativeApi::GetModuleHandleW &&
              winmock::native_api_call_log[1].call == winmock::NativeApi::GetModuleInformation &&
              winmock::native_api_call_log[2].call == winmock::NativeApi::GetModuleBaseNameW &&
              winmock::native_api_call_log[3].call == winmock::NativeApi::GetModuleFileNameExW,
          "local main-module resolution records GetModuleHandleW and metadata query order");

    winmock::reset();
    winmock::module_mode = winmock::ModuleMode::Growing;
    auto growing = ModuleCatalog::snapshot(*process);
    check(!growing && growing.error().code == ErrorCode::PartialTransfer && winmock::module_calls == 5,
          "ModuleCatalog refuses a truncated result after five growing snapshots");

    winmock::reset();
    winmock::module_mode = winmock::ModuleMode::Misaligned;
    auto misaligned = ModuleCatalog::snapshot(*process);
    check(!misaligned && misaligned.error().code == ErrorCode::PartialTransfer && winmock::module_calls == 1,
          "ModuleCatalog rejects non-HMODULE-aligned byte counts");

    winmock::reset();
    winmock::snapshot_error = ERROR_ACCESS_DENIED;
    auto snapshot_failure = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
    check(!snapshot_failure && snapshot_failure.error().operation == "CreateToolhelp32Snapshot" &&
              snapshot_failure.error().native == ERROR_ACCESS_DENIED,
          "strict thread policy reports snapshot creation failure");

    winmock::reset();
    winmock::thread_first_error = ERROR_ACCESS_DENIED;
    auto first_failure = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
    check(!first_failure && first_failure.error().operation == "Thread32First" &&
              first_failure.error().native == ERROR_ACCESS_DENIED && winmock::close_handle_calls == 1,
          "strict thread policy reports Thread32First failure and closes snapshot");

    winmock::reset();
    winmock::open_thread_error = ERROR_ACCESS_DENIED;
    auto open_failure = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
    check(!open_failure && open_failure.error().operation == "OpenThread" &&
              open_failure.error().native == ERROR_ACCESS_DENIED && winmock::close_handle_calls == 1,
          "strict thread policy reports OpenThread failure and closes snapshot");

    winmock::reset();
    winmock::open_thread_error = ERROR_ACCESS_DENIED;
    auto best_effort_open_failure = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersBestEffort);
    check(best_effort_open_failure && best_effort_open_failure->handles().empty() &&
              winmock::close_handle_calls == 1,
          "best-effort thread policy tolerates OpenThread failure and closes snapshot");

    winmock::reset();
    winmock::open_thread_error = ERROR_INVALID_PARAMETER;
    auto exited_thread = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
    check(exited_thread && exited_thread->handles().empty(),
          "strict thread policy tolerates thread-exited OpenThread race");

    winmock::reset();
    winmock::thread_next_error = static_cast<int>(ERROR_ACCESS_DENIED);
    auto strict_threads = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
    check(!strict_threads && strict_threads.error().code == ErrorCode::ThreadEnumerationFailed &&
              strict_threads.error().operation == "Thread32Next" && strict_threads.error().native == ERROR_ACCESS_DENIED,
          "strict thread policy reports unexpected Thread32Next failure");

    winmock::reset();
    winmock::thread_next_error = static_cast<int>(ERROR_NO_MORE_FILES);
    auto normal_threads = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
    constexpr DWORD required_thread_access =
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | SYNCHRONIZE;
    check(normal_threads && normal_threads->handles().size() == 1 &&
              (winmock::last_open_thread_access & required_thread_access) == required_thread_access &&
              (winmock::last_open_thread_access & THREAD_SET_CONTEXT) == 0,
          "native strict thread policy requests suspend/context/wait rights without context-write");

    winmock::reset();
    winmock::thread_next_error = static_cast<int>(ERROR_NO_MORE_FILES);
    auto detours_threads = ScopedThreadList::collect_other_threads(
        ThreadPolicy::SuspendOthersStrict, true);
    constexpr DWORD detours_thread_access =
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | SYNCHRONIZE;
    check(detours_threads && detours_threads->handles().size() == 1 &&
              (winmock::last_open_thread_access & detours_thread_access) == detours_thread_access,
          "Detours thread enumeration requests SetThreadContext access");

    winmock::reset();
    winmock::thread_next_error = static_cast<int>(ERROR_ACCESS_DENIED);
    auto best_effort_threads = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersBestEffort);
    check(best_effort_threads && best_effort_threads->handles().size() == 1,
          "best-effort thread policy tolerates an unexpected enumeration end");

    winmock::reset();
    {
        auto suspended = tessera::detail::native_hook::SuspendedThreads::acquire(ThreadPolicy::SuspendOthersStrict);
        check(suspended && winmock::suspend_thread_calls == 1 &&
                  suspended->ensure_outside(0x1000, 0x100, 0x2000, 0x100).has_value() &&
                  winmock::get_thread_context_calls == 1,
              "native thread suspension succeeds and checks instruction pointers");
        if (suspended) suspended->resume();
        check(winmock::resume_thread_calls == 1,
              "native thread suspension explicitly resumes acquired threads");
    }

    winmock::reset();
    winmock::suspend_thread_error = ERROR_ACCESS_DENIED;
    auto strict_suspend_failure = tessera::detail::native_hook::SuspendedThreads::acquire(
        ThreadPolicy::SuspendOthersStrict);
    check(!strict_suspend_failure &&
              strict_suspend_failure.error().operation == "SuspendThread" &&
              strict_suspend_failure.error().native == ERROR_ACCESS_DENIED,
          "strict native thread policy reports injected SuspendThread failure");

    winmock::reset();
    winmock::suspend_thread_error = ERROR_ACCESS_DENIED;
    auto best_effort_suspend_failure = tessera::detail::native_hook::SuspendedThreads::acquire(
        ThreadPolicy::SuspendOthersBestEffort);
    check(best_effort_suspend_failure.has_value() && winmock::suspend_thread_calls == 1,
          "best-effort native thread policy tolerates injected SuspendThread failure");

    winmock::reset();
    winmock::create_thread_during_suspend = true;
    auto snapshot_race = tessera::detail::native_hook::SuspendedThreads::acquire(
        ThreadPolicy::SuspendOthersStrict);
    check(snapshot_race && winmock::snapshot_thread_count == 1 && winmock::thread_count == 2 &&
              winmock::thread_next_calls == 1 && winmock::suspend_thread_calls == 1,
          "thread created after snapshot capture is outside the finite suspension set");
    if (snapshot_race) snapshot_race->resume();

    bool repeated_snapshot_race_ok = true;
    for (int iteration = 0; iteration < 32; ++iteration) {
        winmock::reset();
        winmock::thread_count = 4;
        winmock::create_threads_during_enumeration_count = 3;
        winmock::create_threads_during_suspend_count = 3;
        winmock::create_threads_during_context_count = 3;
        {
            auto repeated_snapshot_race = tessera::detail::native_hook::SuspendedThreads::acquire(
                ThreadPolicy::SuspendOthersStrict);
            const bool captured_only_snapshot_threads =
                repeated_snapshot_race && winmock::snapshot_thread_count == 4 &&
                winmock::thread_count == 10 && winmock::open_thread_calls == 4 &&
                winmock::suspend_thread_calls == 4 && winmock::thread_next_calls == 4;
            if (!captured_only_snapshot_threads) {
                repeated_snapshot_race_ok = false;
                break;
            }
            const auto context_status = repeated_snapshot_race->ensure_outside(
                0x1000, 0x100, 0x2000, 0x100);
            if (!context_status || winmock::get_thread_context_calls != 4 ||
                winmock::thread_count != 13) {
                repeated_snapshot_race_ok = false;
                break;
            }
            // Model host-created threads after the final IP check and before
            // the patch write. They are outside the already captured snapshot.
            winmock::thread_count += 3;
            if (winmock::thread_count != 16 || winmock::snapshot_thread_count != 4 ||
                winmock::suspend_thread_calls != 4 || winmock::get_thread_context_calls != 4) {
                repeated_snapshot_race_ok = false;
                break;
            }
            repeated_snapshot_race->resume();
        }
        if (winmock::resume_thread_calls != 4 || winmock::close_handle_calls != 5) {
            repeated_snapshot_race_ok = false;
            break;
        }
    }
    check(repeated_snapshot_race_ok,
          "repeated thread creation during enumeration, suspend, context, and patch windows stays outside the finite snapshot");

    winmock::reset();
    winmock::thread_count = 2;
    winmock::suspend_thread_fail_on_call = 2;
    auto partial_suspend_failure = tessera::detail::native_hook::SuspendedThreads::acquire(
        ThreadPolicy::SuspendOthersStrict);
    check(!partial_suspend_failure && partial_suspend_failure.error().operation == "SuspendThread" &&
              winmock::thread_next_calls == 2 && winmock::suspend_thread_calls == 2 &&
              winmock::resume_thread_calls == 1 && winmock::close_handle_calls == 3,
          "strict partial-suspend failure resumes prior threads and closes both thread handles plus snapshot");

    winmock::reset();
    winmock::get_thread_context_error = ERROR_ACCESS_DENIED;
    {
        auto suspended = tessera::detail::native_hook::SuspendedThreads::acquire(ThreadPolicy::SuspendOthersStrict);
        auto context_error = suspended
            ? suspended->ensure_outside(0x1000, 0x100, 0x2000, 0x100)
            : Status{std::unexpected(suspended.error())};
        check(suspended && !context_error &&
                  context_error.error().operation == "GetThreadContext" &&
                  context_error.error().native == ERROR_ACCESS_DENIED,
              "strict native thread policy reports injected GetThreadContext failure");
    }
    check(winmock::resume_thread_calls == 1,
          "native thread context failure still resumes suspended threads during cleanup");

#if defined(__linux__)
    const pid_t resume_failure_child = ::fork();
    if (resume_failure_child == 0) {
        std::set_terminate([]() noexcept { ::_exit(86); });
        winmock::reset();
        winmock::resume_thread_error = ERROR_ACCESS_DENIED;
        winmock::wait_for_single_object_result = WAIT_TIMEOUT;
        auto child_threads = tessera::detail::native_hook::SuspendedThreads::acquire(
            ThreadPolicy::SuspendOthersStrict);
        if (!child_threads) ::_exit(87);
        child_threads->resume();
        ::_exit(88);
    }
    int resume_failure_status = 0;
    const pid_t waited_child = resume_failure_child > 0
        ? ::waitpid(resume_failure_child, &resume_failure_status, 0)
        : -1;
    check(waited_child == resume_failure_child && WIFEXITED(resume_failure_status) &&
              WEXITSTATUS(resume_failure_status) == 86,
          "ResumeThread failure with a live thread invokes the fail-stop terminate policy");
#endif

#if defined(__linux__)
    const pid_t snapshot_close_failure_child = ::fork();
    if (snapshot_close_failure_child == 0) {
        std::set_terminate([]() noexcept { ::_exit(89); });
        winmock::reset();
        winmock::thread_first_error = ERROR_ACCESS_DENIED;
        winmock::close_handle_fail_on_call = 1;
        (void)ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
        ::_exit(90);
    }
    int snapshot_close_status = 0;
    const pid_t snapshot_close_waited = snapshot_close_failure_child > 0
        ? ::waitpid(snapshot_close_failure_child, &snapshot_close_status, 0)
        : -1;
    check(snapshot_close_waited == snapshot_close_failure_child &&
              WIFEXITED(snapshot_close_status) && WEXITSTATUS(snapshot_close_status) == 89,
          "snapshot handle close failure invokes the fail-stop cleanup policy");

    const pid_t thread_close_failure_child = ::fork();
    if (thread_close_failure_child == 0) {
        std::set_terminate([]() noexcept { ::_exit(91); });
        winmock::reset();
        winmock::close_handle_fail_on_call = 2; // Snapshot closes first; owned thread handle closes second.
        {
            auto owned_threads = ScopedThreadList::collect_other_threads(ThreadPolicy::SuspendOthersStrict);
            if (!owned_threads) ::_exit(92);
        }
        ::_exit(93);
    }
    int thread_close_status = 0;
    const pid_t thread_close_waited = thread_close_failure_child > 0
        ? ::waitpid(thread_close_failure_child, &thread_close_status, 0)
        : -1;
    check(thread_close_waited == thread_close_failure_child &&
              WIFEXITED(thread_close_status) && WEXITSTATUS(thread_close_status) == 91,
          "owned thread handle close failure invokes the fail-stop cleanup policy");
#endif

#if defined(__linux__)
    const pid_t mutex_release_failure_child = ::fork();
    if (mutex_release_failure_child == 0) {
        std::set_terminate([]() noexcept { ::_exit(94); });
        winmock::reset();
        winmock::release_mutex_error = ERROR_ACCESS_DENIED;
        { ProcessWideHookLock lock; }
        ::_exit(95);
    }
    int mutex_release_status = 0;
    const pid_t mutex_release_waited = mutex_release_failure_child > 0
        ? ::waitpid(mutex_release_failure_child, &mutex_release_status, 0)
        : -1;
    check(mutex_release_waited == mutex_release_failure_child &&
              WIFEXITED(mutex_release_status) && WEXITSTATUS(mutex_release_status) == 94,
          "owned process mutex release failure invokes the fail-stop cleanup policy");

    const pid_t mutex_close_failure_child = ::fork();
    if (mutex_close_failure_child == 0) {
        std::set_terminate([]() noexcept { ::_exit(96); });
        winmock::reset();
        winmock::close_handle_fail_on_call = 1;
        { ProcessWideHookLock lock; }
        ::_exit(97);
    }
    int mutex_close_status = 0;
    const pid_t mutex_close_waited = mutex_close_failure_child > 0
        ? ::waitpid(mutex_close_failure_child, &mutex_close_status, 0)
        : -1;
    check(mutex_close_waited == mutex_close_failure_child &&
              WIFEXITED(mutex_close_status) && WEXITSTATUS(mutex_close_status) == 96,
          "owned process mutex close failure invokes the fail-stop cleanup policy");
#endif

    winmock::reset();
    winmock::detour_update_error = 1234;
    HookOptions hook_options{};
    hook_options.threads = ThreadPolicy::SuspendOthersStrict;
    auto attach_error = default_hook_backend().attach(Address{0x1000}, reinterpret_cast<void*>(0x2000), hook_options);
    check(!attach_error && attach_error.error().operation == "DetourUpdateThread" &&
              attach_error.error().native == 1234 && winmock::detour_abort_calls == 1 &&
              winmock::detour_attach_calls == 0 &&
              (winmock::last_open_thread_access & THREAD_SET_CONTEXT) != 0,
          "Detours attach requests context-write access and reports update failure accurately");

    winmock::reset();
    winmock::detour_update_error = 2345;
    HookToken token{};
    token.target = reinterpret_cast<void*>(0x1000);
    token.detour = reinterpret_cast<void*>(0x2000);
    token.trampoline = reinterpret_cast<void*>(0x3000);
    token.threads = ThreadPolicy::SuspendOthersStrict;
    auto detach_error = default_hook_backend().detach(token);
    check(!detach_error && detach_error.error().operation == "DetourUpdateThread" &&
              detach_error.error().native == 2345 && winmock::detour_abort_calls == 1 &&
              winmock::detour_detach_calls == 0 &&
              (winmock::last_open_thread_access & THREAD_SET_CONTEXT) != 0,
          "Detours detach requests context-write access and reports update failure accurately");

    winmock::reset();
    auto attached = default_hook_backend().attach(Address{0x1000}, reinterpret_cast<void*>(0x2000), hook_options);
    check(attached.has_value() && attached->trampoline == reinterpret_cast<void*>(0x1000),
          "Detours attach mock success path returns a hook token");
    if (attached) {
        auto detached = default_hook_backend().detach(*attached);
        check(detached.has_value(), "Detours detach mock success path completes");
    }

    std::printf("WINDOWS_MOCK_RESULT %s (%d failures)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
