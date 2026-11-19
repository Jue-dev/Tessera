# Portable validation (Linux / server)

Portable validation runs project-provided build and test commands in a Linux
environment. It is supplemental and does **not** emulate Windows, the Windows
loader, unwind registration, executable memory, or native inline-hook runtime
behavior.

## Recommended interface

Google Colab is no longer the recommended test console: its notebook layout is
not suitable for mobile screens, and it runs commands in a notebook runtime.

The planned replacement is a responsive, self-hosted web console. Its security
and deployment requirements are tracked in
[validation-server.md](validation-server.md). The console must keep GitHub
credentials server-side, authenticate users, and run test commands in disposable,
resource-limited containers. The server implementation and deployment have not
yet been completed or security-validated.

## Current Tessera portable test profile

1. GCC strict mock build and test:
   `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang/libc++ strict mock:
   `EXTRA_CXXFLAGS='-stdlib=libc++' CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh`
3. GCC AddressSanitizer + UndefinedBehaviorSanitizer:
   `EXTRA_CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' bash verify/windows_mock/run_windows_mock_tests.sh`

A result of `PASS` means all configured tests ran and passed.
`PARTIAL` means no test failed, but at least one test was skipped.
`FAIL` means cloning, configuration, setup, or a test failed.

## Run locally on Linux

From the repository root:

```bash
bash verify/windows_mock/run_windows_mock_tests.sh
CXX=clang++ EXTRA_CXXFLAGS='-stdlib=libc++' bash verify/windows_mock/run_windows_mock_tests.sh
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

These remain pending until a Windows runner produces results for the exact PR
head. Portable Linux results are not evidence for these Windows-native gates.
