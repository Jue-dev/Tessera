# Portable validation (Google Colab free runtime)

Portable validation runs project-provided build and test commands in a Linux
environment. It is supplemental and does **not** emulate Windows, the Windows
loader, unwind registration, executable memory, or native inline-hook runtime
behavior.

## Colab notebook console

Open the
[Tessera Portable Validation notebook](../verify/portable/Tessera_Portable_Validation.ipynb)
in Google Colab. The notebook uses compact native widgets instead of wide
notebook forms or custom external web panels:

- Mobile-friendly single-column controls.
- Dynamically add/remove setup commands and tests.
- Repository URL, branch/ref, Colab Secret name, clone depth and timeouts.
- Continue-on-failure and workspace retention.
- Summary, expandable logs, full copyable report, and download.
- GitHub token read from Colab Secrets and removed from the environment after
  cloning, before setup/test commands.

Add the GitHub token in Colab's Secrets panel (default name `GH_TOKEN`) and
grant the notebook access to it. For a private repository, use a fine-grained
token restricted to Tessera with read-only Contents permission. Do not paste a
token into notebook cells, test commands, or repository URLs.

**Security warning:** setup/test commands execute arbitrary shell code inside
your Colab runtime. Run only trusted code. The token is used during clone and
must never be used to test untrusted pull requests. Colab's managed runtime is
ephemeral and can disconnect; reports are saved under
`/content/PROJECT_VALIDATION_REPORT.txt` for download during the session.

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
