# Portable validation (Linux / Google Colab)

This is supplemental validation for the Windows-only Tessera project. It runs the
existing `verify/windows_mock` harness against real backend source files with
deterministic Win32 API stubs. It does **not** emulate Windows, loader/unwind
registration, executable memory, or native inline-hook runtime behavior.

## Google Colab

Open [Tessera_Portable_Validation.ipynb](../verify/portable/Tessera_Portable_Validation.ipynb)
in GitHub, download it, then upload/open it in Google Colab. Run all cells.

The notebook pins the checkout to `issue-6/unwind-lifecycle` and performs:

1. GCC build/run with `-Wall -Wextra -Wpedantic -Werror`.
2. Clang build/run with the same strict warnings (installs Clang if needed).
3. GCC AddressSanitizer + UndefinedBehaviorSanitizer run.
4. Prints the latest harness log and checked-out commit.

Each run must exit successfully and end with `WINDOWS_MOCK_VALIDATION_COMPLETE`.
Save the notebook output and log as evidence; do not treat historical logs as
proof of the current revision.

## Run locally on Linux

From the repository root:

```bash
bash verify/windows_mock/run_windows_mock_tests.sh
CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh
EXTRA_CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
bash verify/windows_mock/run_windows_mock_tests.sh
```

## Still requires Windows/MSVC

- x86 and x64 Debug/Release CMake build + CTest
- Real native inline-hook attach, trampoline execution, detach, and rollback
- x64 unwind/function-table registration and exception behavior
- DLL unload/admission-drain lifecycle tests
- Live Microsoft Detours integration
- MSVC `/analyze`, SDK install/consumer tests, and Windows-specific fuzz smoke

These remain pending until a Windows runner produces results for the exact PR head.
