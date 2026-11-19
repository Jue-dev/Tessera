# Portable validation (Linux / Google Colab)

Portable validation runs project-provided build and test commands in a Linux
environment. It is supplemental and does **not** emulate Windows, the Windows
loader, unwind registration, executable memory, or native inline-hook runtime
behavior.

## Google Colab — native form notebook

Open
[Tessera_Portable_Validation.ipynb](../verify/portable/Tessera_Portable_Validation.ipynb)
in Google Colab. The notebook has two cells: a short guide and one runner cell.
All settings use Google Colab's native `#@param` form controls; it does not
depend on ipywidgets or a separate HTML/web UI.

The initial form values target the current `issue-6/unwind-lifecycle` branch
and Tessera's portable mock harness. For another project, change the repository
URL, ref, and test commands in the form.

1. For a private GitHub repository, add a Colab Secret named `GH_TOKEN` and
   enable notebook access. A fine-grained token with repository
   `Contents: Read-only` is sufficient for cloning. Public repositories do
   not need a token.
2. Adjust the form fields above the runner cell. Optional setup commands and
   up to five test commands can be entered without editing the Python code.
3. Run the cell. The report is printed directly in the cell output and is also
   saved as `/content/PROJECT_VALIDATION_REPORT.txt`.
4. Copy the report text from the Colab output and paste it into the issue or
   conversation being investigated.

### Test command format

Each test field uses this format:

```text
Test name :: shell command
Compiler test :: CXX=clang++ ./test.sh :: needs=clang++
```

The optional `needs=` section checks that required executables exist. Missing
executables are marked `SKIP`, not test failures. Clang installation is
enabled by default only when a configured test requires `clang++` and it is
not installed; this can be disabled in the form. Three optional setup command
fields run before tests.

The runner records repository, ref, exact commit SHA, platform, duration,
commands, exit codes, captured output, and an issue pool. Tokens are used only
for cloning, removed from the clone environment before test commands run, and
redacted from captured clone output. User-configured setup and test commands
execute as shell commands in Colab; run only commands and repositories you
trust.

## Current Tessera portable test profile

The default test fields run:

1. GCC strict mock build and test:
   `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang strict mock build and test:
   `CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh`
3. GCC AddressSanitizer + UndefinedBehaviorSanitizer build and test.

The Clang test declares `needs=clang++`; if the compiler is missing, the
notebook installs it by default before running the test (unless disabled).

A result of `PASS` means all configured tests ran and passed.
`PARTIAL` means no test failed, but at least one test was skipped.
`FAIL` means cloning, configuration, setup, or a test failed.

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
