# Portable validation (Linux / Google Colab)

Portable validation is supplemental. It can build and run project-provided test
commands in a Linux environment, but it does **not** emulate Windows, the
Windows loader, unwind registration, executable memory, or native inline-hook
runtime behavior.

## Google Colab — Project Test Console

Open
[Tessera_Portable_Validation.ipynb](../verify/portable/Tessera_Portable_Validation.ipynb)
in Google Colab. The notebook is a compact two-cell console: a short guide and
one configurable panel. Its initial settings target the current
`issue-6/unwind-lifecycle` branch and the Tessera portable mock harness, but
the repository URL, ref, setup commands, test commands, compiler requirements,
timeouts, and workspace behavior can all be changed for another project.

1. For a private GitHub repository, add a Colab Secret named `GH_TOKEN` and
   enable notebook access. A fine-grained token with repository
   `Contents: Read-only` is sufficient for cloning. Public repositories do
   not need a token.
2. Run the panel cell once. Change settings if needed, then press **Testleri
   çalıştır**.
3. When complete, press **Raporu kopyala** and paste the complete report into
   the issue or conversation being investigated.

Test commands use one line each in this format:

```text
Test name :: shell command
Compiler test :: command :: needs=clang++
```

The optional `needs=` field checks for required executables. When a required
tool is unavailable, that test is marked `SKIP`; it is not reported as a test
failure. Clang installation is available as an opt-in setting. Setup commands
are also configurable, one shell command per line.

The runner records the repository, branch, exact commit SHA, environment,
duration, commands, exit codes, captured output, and an issue pool. The report
copy button uses the browser clipboard; if the browser blocks clipboard
access, select the report text area and copy it manually. Tokens are used only
for cloning, removed from the clone environment before test commands run, and
redacted from captured clone output. Only run trusted repositories and
commands: user-configured setup and test commands execute in the Colab runtime.

## Current Tessera portable test profile

The default command set runs:

1. GCC strict mock build and test:
   `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang strict mock build and test (skipped when `clang++` is unavailable,
   unless the opt-in installation setting is enabled).
3. GCC AddressSanitizer + UndefinedBehaviorSanitizer build and test.

A result of `PASS` means all configured tests ran and passed.
`PARTIAL` means no test failed, but at least one configured test was skipped.
`FAIL` means cloning, setup, configuration, or a test failed.

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

These remain pending until a Windows runner produces results for the exact PR
head. Portable Linux results are not evidence for these Windows-native gates.
