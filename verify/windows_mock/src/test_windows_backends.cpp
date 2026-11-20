#include <Windows.h>

#include <cstdio>
#include <cstdlib>
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

    winmock::reset();
    winmock::process_machine = IMAGE_FILE_MACHINE_I386;
    auto wow64_process = from_native_handle(reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x45)),
                                            Ownership::Borrowed);
    check(wow64_process && wow64_process->info().architecture == Architecture::X86 &&
              wow64_process->info().pointer_size == 4,
          "Process backend identifies a 32-bit target on an x64 host");
    winmock::reset();
    winmock::native_machine = IMAGE_FILE_MACHINE_ARM64;
    auto unsupported_process = from_native_handle(reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x46)),
                                                  Ownership::Borrowed);
    check(!unsupported_process && unsupported_process.error().code == ErrorCode::UnsupportedArchitecture,
          "Process backend rejects unsupported native architectures");

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
    winmock::max_read_chunk = 2;
    std::array<std::byte, 4> partial_buffer{};
    auto partial = memory_reader.read_partial(Address{0x1000}, partial_buffer);
    check(partial && *partial == 2, "Windows memory backend reports partial ReadProcessMemory transfer");

    winmock::reset();
    auto modules = ModuleCatalog::snapshot(*process);
    check(modules.has_value() && modules->size() == 2, "stable ModuleCatalog snapshot returns both modules");
    if (modules && modules->size() == 2) {
        check(modules->at(0).size() == 0x2000 && modules->at(1).size() == 0x2000 &&
                  modules->at(0).base() != modules->at(1).base(),
              "ModuleCatalog returns distinct module image ranges");
    }

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
