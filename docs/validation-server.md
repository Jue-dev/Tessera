# Colab-hosted Tessera validation console

The console runs a small HTTP server **inside the active Google Colab runtime**.
The notebook starts the server and prints a Colab port-proxy URL. The user opens
that URL in a separate browser tab; the validation UI is not rendered inside a
notebook iframe and commands remain on the Colab runtime.

This is not a permanent public deployment, VPS, or external tunnel. The proxy
URL is session-scoped and only works for the current Colab user while the
notebook/runtime remains available. Runtime disconnections stop the server and
discard its in-memory job state. A new URL is generated after restarting.

## Interface

- Standalone responsive web UI, dark by default, with restrained navy/slate
  surfaces, cyan/teal accents, clear status indicators, and mobile layouts.
- Repository/ref and Colab Secret configuration.
- Dynamic setup-command and test rows; no fixed row limit.
- Server-side clone, setup, and test execution in the notebook runtime.
- Progress summary, per-step output, and downloadable text report.
- No notebook iframe and no third-party UI/CDN dependency.

## Server and access model

- The server binds to the Colab kernel and is exposed only through Colab's
  authenticated port proxy. The generated URL includes a high-entropy,
  per-runtime path secret; it is not a reusable deployment URL.
- No public tunnel, port-forwarding service, or separate VPS is created.
- The server stops when the Colab runtime stops. The URL is not intended for
  sharing with other users.
- The UI path secret is separate from the GitHub token. Never paste the GitHub
  token into the UI URL.
- Colab's own browser/port-proxy behavior can change. The notebook prints the
  runtime-generated URL and a direct open-in-new-tab link. If Colab or the
  browser blocks opening a separate tab, use the visible URL in a new tab; do
  not fall back to a public tunnel.

## Security and execution

- Add the GitHub token to Colab Secrets (default name `GH_TOKEN`). The token
  is used only for cloning via a temporary askpass helper; the helper is
  deleted and credential environment variables are not passed to setup/tests.
- Test processes receive a sanitized copy of the runtime environment. Tokens,
  passwords, and secret-named environment variables are removed.
- Colab Secrets are **not an isolation boundary** against arbitrary code
  running in the same notebook runtime. Malicious setup/test code can interact
  with notebook APIs and potentially access secrets. Run only trusted
  repositories and commands; do not run untrusted pull-request code in a
  runtime where a token is available.
- Enforce clone/test timeouts, output clipping, credential redaction, and
  optional workspace cleanup.
- Runtime files are ephemeral. Download reports before disconnecting.

## Current Tessera portable test profile

1. GCC strict mock: `bash verify/windows_mock/run_windows_mock_tests.sh`
2. Clang/libc++ strict mock:
   `EXTRA_CXXFLAGS='-stdlib=libc++' CXX=clang++ bash verify/windows_mock/run_windows_mock_tests.sh`
3. GCC ASan/UBSan:
   `EXTRA_CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' bash verify/windows_mock/run_windows_mock_tests.sh`

Portable Linux mock tests are supplementary. They do not validate native Windows
/MSVC, loader, unwind registration, executable-memory, or hook lifecycle behavior.
