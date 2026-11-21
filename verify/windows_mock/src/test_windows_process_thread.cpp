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

void run_process_tests() {
    using namespace tessera;
    using namespace tessera::platform::windows;
    // The diagnostic log is intentionally bounded, but failure ordinals must
    // remain accurate after its storage fills.
    winmock::reset();
    winmock::fail_native_api = winmock::NativeApi::OpenProcess;
    winmock::fail_native_api_on_call = 2;
    for (int i = 0; i < 64; ++i) {
        (void)winmock::record_native_api_call(winmock::NativeApi::GetNativeSystemInfo, nullptr);
    }
    const bool first_open_recorded =
        winmock::record_native_api_call(winmock::NativeApi::OpenProcess, nullptr);
    const bool second_open_failed =
        winmock::record_native_api_call(winmock::NativeApi::OpenProcess, nullptr);
    check(!first_open_recorded && second_open_failed && winmock::native_api_call_count == 66,
          "per-API indexed failure remains correct after the bounded diagnostic log fills");
    winmock::reset();

    // Process-open contract: required query-limited access is always requested,
    // while the caller's requested VM rights and PID are preserved exactly.
    winmock::reset();
    auto opened_process = Process::open(ProcessId{123}, ProcessAccess::Read);
    constexpr DWORD expected_process_access = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
    check(opened_process && winmock::native_api_call_count >= 5 &&
              winmock::native_api_call_log[0].call == winmock::NativeApi::OpenProcess &&
              winmock::native_api_call_log[0].argument1 == expected_process_access &&
              winmock::native_api_call_log[0].argument2 == FALSE &&
              winmock::native_api_call_log[0].argument3 == 123 &&
              winmock::native_api_call_log[1].call == winmock::NativeApi::GetProcessId &&
              winmock::native_api_call_log[1].handle == 0x44 &&
              winmock::native_api_call_log[2].call == winmock::NativeApi::IsWow64Process2 &&
              winmock::native_api_call_log[2].handle == 0x44 &&
              winmock::native_api_call_log[3].call == winmock::NativeApi::GetExitCodeProcess &&
              winmock::native_api_call_log[4].call == winmock::NativeApi::GetNativeSystemInfo,
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
}

void run_thread_tests() {
    using namespace tessera;
    using namespace tessera::platform::windows;
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
}

} // namespace winmock_tests
