#pragma once

#include <cstdio>

#include "api_stubs.hpp"
#include "tessera/process/process.hpp"

namespace winmock_tests {

inline int failures = 0;

inline void check(bool condition, const char* name) {
    if (condition) {
        std::printf("PASS %s\n", name);
    } else {
        std::printf("FAIL %s\n", name);
        ++failures;
    }
}

void run_process_tests();
void run_memory_module_tests(const tessera::Result<tessera::Process>& process);
void run_thread_tests();
void run_detours_hook_tests();

} // namespace winmock_tests
