# Windows backend mock validation

This is a host-side test harness for selected Windows-native backend control paths. It compiles the actual Tessera Windows backend `.cpp` files against a small, test-only Win32/PSAPI/Toolhelp/Detours API surface and links deterministic API stubs.

It is **not** a Windows SDK, does not emulate the Windows kernel or loader, and does not replace a Windows/MSVC integration build. It is useful for exercising C++ control flow and error handling on Linux where the real APIs are unavailable.

## Run

From the Tessera repository root:

```bash
./verify/windows_mock/run_windows_mock_tests.sh
```

With Clang 17:

```bash
CXX=clang++ ./verify/windows_mock/run_windows_mock_tests.sh
```

With AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
EXTRA_CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 \
./verify/windows_mock/run_windows_mock_tests.sh
```

## Covered cases

- `Process::from_native_handle` x64 and WOW64/x86 architecture discovery; unsupported host architecture rejection.
- `ReadProcessMemory`, `WriteProcessMemory`, `VirtualQueryEx`, `VirtualProtectEx`, partial read reporting and instruction-cache flush behavior.
- Stable module enumeration, module image ranges, non-HMODULE-aligned sizes, and a module list that grows on every retry.
- Strict versus best-effort `Thread32Next` error handling.
- Native versus Detours thread-handle access masks, including the `THREAD_SET_CONTEXT` right required by Detours transaction commits.
- Native thread suspension success, deterministic snapshot, `Thread32First`, `Thread32Next`, `OpenThread`, `SuspendThread`, and `GetThreadContext` failures, strict/best-effort policy behavior, exited-thread races, and resume cleanup after context-query failure.
- Detours attach/detach success and `DetourUpdateThread` error propagation.

The R8 validation logs record **19/19 checks passing** with GCC 14.2 and Clang 17, including AddressSanitizer and UndefinedBehaviorSanitizer runs; those historical logs are in `verify/portable/logs/windows_mock_R8/`. The current source includes deterministic native thread-suspension failure checks. Run the script to obtain a fresh result for the current source; archived R8 logs do not cover later additions.

The executable under `bin/` was compiled with GCC and ASan/UBSan. The source runner rebuilds it from source; build outputs are written to `build/`.

The `Windows Backend Mock (Linux)` job in `.github/workflows/ci.yml` runs this harness on every relevant pull request and main-branch push; invoke it with `bash verify/windows_mock/run_windows_mock_tests.sh` when the script file mode is not executable.
