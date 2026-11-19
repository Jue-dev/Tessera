# Colab portable validation console

The validation console is intended to run as interactive notebook code inside
Google Colab's own notebook UI. It is **not** a separately hosted web service
or a tunnel to an external web panel.

Google's free managed runtimes prohibit web-service offerings unrelated to
interactive compute and prohibit bypassing the notebook UI to interact primarily
through another web UI. See the official
[Colab FAQ](https://research.google.com/colaboratory/faq.html) for current
restrictions and variable runtime limits.

## Interface requirements

- Keep the controls in notebook output, using compact, responsive widgets.
- Mobile-friendly: no wide tables, side-by-side controls that force horizontal
  scrolling, or raw CSS/HTML source printed as text.
- Dynamic setup commands and tests: add/remove rows, no fixed maximum.
- Provide a readable summary, collapsible test logs, and copy/download report.
- Use Colab Secret for the GitHub token; never print it, put it in URLs, or save
  it in the notebook/settings/report.
- Do not launch an externally accessible web server or tunnel on free Colab.

## Security and execution

- Treat user-provided setup/test commands as arbitrary code. Run only trusted
  repositories and commands.
- The GitHub token is used only for repository checkout. Remove it from the
  environment immediately afterward; avoid credential persistence and redact
  errors/logs.
- Pin the tested commit SHA in the report.
- Enforce clone and test timeouts, output clipping, and cleanup of temporary
  credentials.
- Colab's managed VM is not a security boundary for arbitrary untrusted tests.
  Do not run untrusted PR code with a token present.
- Runtime sessions are ephemeral and may disconnect. Save reports locally for
  download; do not assume files persist between sessions.

## Current Tessera portable test profile

1. GCC strict mock: `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang/libc++ strict mock:
   `EXTRA_CXXFLAGS='-stdlib=libc++' CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh`
3. GCC ASan/UBSan:
   `EXTRA_CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' bash verify/windows_mock/run_windows_mock_tests.sh`

Portable Linux mock tests are supplementary. They do not validate native Windows
/MSVC, loader, unwind, executable-memory, or hook lifecycle behavior.
