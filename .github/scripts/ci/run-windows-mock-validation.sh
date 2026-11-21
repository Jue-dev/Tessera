#!/usr/bin/env bash
set -euo pipefail

bash ./verify/windows_mock/run_windows_mock_tests.sh

EXTRA_CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1" \
bash ./verify/windows_mock/run_windows_mock_tests.sh
