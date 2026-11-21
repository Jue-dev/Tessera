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

void run_detours_hook_tests() {
    using namespace tessera;
    using namespace tessera::platform::windows;
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
    winmock::detour_attach_error = 3456;
    auto transaction_attach_error =
        default_hook_backend().attach(Address{0x1000}, reinterpret_cast<void*>(0x2000), hook_options);
    check(!transaction_attach_error &&
              transaction_attach_error.error().operation == "DetourAttach" &&
              transaction_attach_error.error().native == 3456 &&
              winmock::detour_attach_calls == 1 && winmock::detour_abort_calls == 1,
          "Detours attach failure aborts the transaction and preserves the native error");

    winmock::reset();
    winmock::detour_detach_error = 4567;
    auto transaction_detach_error = default_hook_backend().detach(token);
    check(!transaction_detach_error &&
              transaction_detach_error.error().operation == "DetourDetach" &&
              transaction_detach_error.error().native == 4567 &&
              winmock::detour_detach_calls == 1 && winmock::detour_abort_calls == 1,
          "Detours detach failure aborts the transaction and preserves the native error");

    winmock::reset();
    winmock::detour_commit_error = 5678;
    auto commit_attach_error =
        default_hook_backend().attach(Address{0x1000}, reinterpret_cast<void*>(0x2000), hook_options);
    check(!commit_attach_error &&
              commit_attach_error.error().operation == "DetourTransactionCommit" &&
              commit_attach_error.error().native == 5678 &&
              winmock::detour_abort_calls == 1,
          "Detours attach commit failure aborts the transaction");

    winmock::reset();
    winmock::detour_commit_error = 6789;
    auto commit_detach_error = default_hook_backend().detach(token);
    check(!commit_detach_error &&
              commit_detach_error.error().operation == "DetourTransactionCommit" &&
              commit_detach_error.error().native == 6789 &&
              winmock::detour_abort_calls == 1,
          "Detours detach commit failure aborts the transaction");

    winmock::reset();
    auto attached = default_hook_backend().attach(Address{0x1000}, reinterpret_cast<void*>(0x2000), hook_options);
    check(attached.has_value() && attached->trampoline == reinterpret_cast<void*>(0x1000),
          "Detours attach mock success path returns a hook token");
    if (attached) {
        auto detached = default_hook_backend().detach(*attached);
        check(detached.has_value(), "Detours detach mock success path completes");
    }

}

} // namespace winmock_tests
