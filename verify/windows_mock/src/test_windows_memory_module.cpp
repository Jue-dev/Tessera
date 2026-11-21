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

#include "windows_mock_test_support.hpp"

namespace winmock_tests {

void run_memory_module_tests(const Result<Process>& process) {
    using namespace tessera;
    using namespace tessera::platform::windows;
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
    check(info_api_failure && info_api_failure->size() == 1 &&
              info_api_failure->front().base().value() ==
                  0x100000 + static_cast<std::uintptr_t>(0x222) * 0x10000 &&
              winmock::native_api_call_log[1].call == winmock::NativeApi::GetModuleInformation,
          "GetModuleInformation failure skips only the affected module");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetModuleBaseNameW;
    winmock::fail_native_api_on_call = 1;
    auto base_name_api_failure = ModuleCatalog::snapshot(*process);
    check(base_name_api_failure && base_name_api_failure->size() == 1 &&
              base_name_api_failure->front().base().value() ==
                  0x100000 + static_cast<std::uintptr_t>(0x222) * 0x10000,
          "GetModuleBaseNameW failure skips only the affected module");

    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::GetModuleFileNameExW;
    winmock::fail_native_api_on_call = 1;
    auto path_api_failure = ModuleCatalog::snapshot(*process);
    check(path_api_failure && path_api_failure->size() == 2 &&
              path_api_failure->front().base().value() ==
                  0x100000 + static_cast<std::uintptr_t>(0x111) * 0x10000 &&
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
    check(local_main_module &&
              local_main_module->base().value() ==
                  0x100000 + static_cast<std::uintptr_t>(0x111) * 0x10000 &&
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
}

} // namespace winmock_tests
