# Colab-hosted project validation console

The reusable console runs project-defined setup and test commands in the active
Google Colab runtime. The generic notebook is
[`Project_Validation_Console.ipynb`](../verify/portable/Project_Validation_Console.ipynb).
It starts a local HTTP server and prints a Colab port-proxy URL that opens in a
separate browser tab; the interface is not embedded in a notebook iframe.

## Reusable configuration profiles

- Import a versioned JSON profile with **Load profile**.
- Export the current repository, runtime, setup and test settings with
  **Export profile** to reuse them in another Colab session or project.
- **Restore defaults** clears all project, setup and test fields. The notebook starts blank.
- Profiles include the Colab Secret *name*, never the secret/token value.
  Store credentials in Colab Secrets and review imported shell commands before
  running them.
- GitHub profile loading is configurable by repository (`owner/name`), file path,
  branch/tag/commit ref, and optional Colab Secret name. Public repositories work
  without a token; private repositories require a token with read access. Tessera's
  profile is available at
  [`tessera.portable-validation.json`](../verify/portable/profiles/tessera.portable-validation.json).

The schema is versioned with `schema_version: 1`. It supports project name,
repository URL/ref, Colab Secret name, Git username, clone depth, timeouts,
workspace retention, continue-on-failure, setup commands, and named tests with
optional executable requirements. The profile is a settings file, not a
trusted/sandboxed workflow: its commands execute as shell code in Colab.

## Interface and reports

- Generic responsive dark UI with project identity driven by the loaded profile.
- Dynamic setup-command and test rows.
- Progress metrics and per-step execution logs.
- Full text report with both **Copy report** and **Download report** actions,
  plus an in-page preview and a server-side report text endpoint.
- No notebook iframe and no third-party UI/CDN dependency.

## Server and access model

- The server binds inside the active Colab runtime and is exposed through
  Colab's authenticated port proxy. The generated URL contains a high-entropy,
  per-runtime path secret.
- No public tunnel, port-forwarding service, VPS, or permanent deployment is
  created. The URL expires when the runtime stops.
- The session URL is not intended for sharing with other users. The GitHub
  token is never placed in the URL.
- If the browser blocks opening a separate tab, copy the printed URL into a
  new tab.

## Security and execution

- Add a GitHub token to Colab Secrets (the default name is `GH_TOKEN`). It is
  used for repository checkout through a temporary askpass helper that is
  deleted after cloning.
- Setup/test processes receive a sanitized environment. Token, password and
  credential-named environment variables are removed before commands execute.
- Colab Secrets are **not an isolation boundary** against arbitrary code in
  the same runtime. Malicious setup/test commands can interact with notebook
  APIs and may access secrets. Run only trusted repositories and commands.
- Clone and step timeouts, output clipping, credential redaction and optional
  workspace cleanup are applied.
- Runtime state and files are ephemeral. Download or copy reports before
  disconnecting.

## Tessera default profile limits

The included profile runs the portable Linux mock suite only. A Linux mock
`PASS` is not evidence of native Windows/MSVC behavior. The following still
require a Windows runner:

- x86/x64 Debug and Release CMake builds plus CTest
- Native inline-hook attach, trampoline execution, detach and rollback
- x64 unwind/function-table registration and exception behavior
- DLL unload/admission-drain lifecycle tests
- Live Microsoft Detours integration
- MSVC static analysis and Windows SDK install/consumer checks


## GitHub Actions automation

The manual `Project Validation` workflow reads a JSON profile, resolves repository/ref overrides, checks out the target repository, runs setup/test commands, writes a report, adds it to the Actions summary, and uploads it as an artifact. Private target repositories may require the `VALIDATION_GH_TOKEN` repository secret.
