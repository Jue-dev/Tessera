# Portable validation (Linux / Google Colab)

Portable validation runs project-provided build and test commands in a Linux
environment. It is supplemental and does **not** emulate Windows, the Windows
loader, unwind registration, executable memory, or native inline-hook runtime
behavior.

## Google Colab — reusable Project Test Console

Open
[Tessera_Portable_Validation.ipynb](../verify/portable/Tessera_Portable_Validation.ipynb)
in Google Colab. Settings use native Colab form controls, grouped into six
sections; there is no custom web UI or ipywidgets dependency.

### Configuration sections

1. **Project** — profile, repository URL, branch/ref.
2. **Git access** — Colab Secret name, username, clone depth, clone timeout.
3. **Runtime** — test timeout, optional Clang/libc++ installation, continue-on-failure, workspace retention.
4. **Setup** — up to three shell setup commands.
5. **Test matrix** — up to five named test commands with optional required executable declarations.
6. **Reuse / saved settings** — optional Drive JSON load/save.

For private GitHub repositories, add a Colab Secret (default `GH_TOKEN`) and
enable notebook access. Fine-grained token repository permission
`Contents: Read-only` is sufficient for cloning. Public repositories do not
need a token.

### Saved settings

Enable **Use Drive settings** to mount Google Drive. The settings JSON path
defaults to `/content/drive/MyDrive/ProjectTestConsole/settings.json`.
Enable **Load saved settings** to use a saved configuration, and
**Save settings after run** to persist the current values. Do not store tokens
in the settings file; authentication is read separately from Colab Secrets.

### Test command format

Each test field uses:

```text
Test name :: shell command :: needs=program
```

The `needs=` suffix is optional. If a required executable is missing, that
test is marked `SKIP`. Clang and libc++ installation are opt-in form settings.
Setup and test commands execute in the Colab shell; run only trusted commands.

### Report

The runner prints a compact summary (overall status, PASS/FAIL/SKIP counts,
repository, ref, commit, duration) followed by the complete copyable report.
The report is also saved to `/content/PROJECT_VALIDATION_REPORT.txt`.
Package-install output is truncated to keep reports manageable. The report
includes test output, exit codes, durations, environment and Issue Pool.

## Current Tessera portable test profile

The default profile runs:

1. GCC strict mock build and test:
   `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang strict mock using libc++:
   `EXTRA_CXXFLAGS='-stdlib=libc++' CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh`
3. GCC AddressSanitizer + UndefinedBehaviorSanitizer.

The Clang profile uses libc++ to provide C++23 `std::expected` support for
toolchains whose default libstdc++ headers do not expose it. Installation can be
enabled in the form settings.

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
