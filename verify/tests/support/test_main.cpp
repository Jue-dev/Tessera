#include "catch2/catch_test_macros.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#if defined(_MSC_VER)
#include <crtdbg.h>
#endif

int main() {
#if defined(_MSC_VER)
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#if defined(_DEBUG)
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
#endif
#endif
    int passed = 0;
    int failed = 0;
    const auto& tests = ::tessera::test_runner::registry();

    for (const auto& tc : tests) {
        std::printf("[RUN ] %s\n", tc.name);
        std::fflush(stdout);
        const int checks_before = ::tessera::test_runner::check_failure_counter();
        try {
            tc.fn();
            if (::tessera::test_runner::check_failure_counter() == checks_before) {
                ++passed;
            } else {
                ++failed;
                std::fprintf(stderr, "[FAILED] %s (check failure)\n", tc.name);
            }
        } catch (const ::tessera::test_runner::FailureException& ex) {
            ++failed;
            std::fprintf(stderr, "[FAILED] %s\n  %s\n", tc.name, ex.what());
        } catch (const std::exception& ex) {
            ++failed;
            std::fprintf(stderr, "[FAILED] %s (unexpected exception: %s)\n", tc.name, ex.what());
        } catch (...) {
            ++failed;
            std::fprintf(stderr, "[FAILED] %s (unknown exception)\n", tc.name);
        }
    }

    std::printf("===============================================================================\n");
    if (failed == 0) {
        std::printf("All tests passed (%d assertions in %d test cases)\n",
                    ::tessera::test_runner::assertion_counter(),
                    passed);
        return 0;
    }
    std::fprintf(stderr,
                 "test cases: %d | %d passed | %d failed\n",
                 passed + failed,
                 passed,
                 failed);
    return 1;
}
