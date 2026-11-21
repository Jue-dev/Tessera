#include <Windows.h>

#include <cstdint>
#include <cstdio>

#include "tessera/platform/windows/native.hpp"
#include "windows_mock_test_support.hpp"

int main() {
    using namespace tessera;
    using namespace tessera::platform::windows;

    auto process = from_native_handle(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x44)), Ownership::Borrowed);
    winmock_tests::check(process.has_value(), "from_native_handle builds a mock x64 Process");
    if (!process) {
        return 2;
    }

    winmock_tests::run_process_tests();
    winmock_tests::run_memory_module_tests(process);
    winmock_tests::run_thread_tests();
    winmock_tests::run_detours_hook_tests();

    std::printf("WINDOWS_MOCK_RESULT %s (%d failures)\n",
                winmock_tests::failures == 0 ? "PASS" : "FAIL",
                winmock_tests::failures);
    return winmock_tests::failures == 0 ? 0 : 1;
}
