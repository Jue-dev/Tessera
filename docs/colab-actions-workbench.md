# Colab Actions Workbench

The notebook at `verify/colab_actions/Colab_Actions_Workbench.ipynb` provides a Colab-side workflow interpreter. It reads workflow YAML from the checked-out repository's `.github/workflows/` directory and runs the supported subset on the active Google Colab Linux runtime. It does **not** dispatch GitHub Actions, so it does not consume Actions minutes.

## Start

1. Open the notebook in Google Colab and run its launcher cell.
2. Public repositories can be cloned without a token. For private repository access and repository/branch discovery, add a fine-grained GitHub token to Colab Secrets under the name `GH_TOKEN` (or change the secret-name field in the UI).
3. Select the repository and ref, then choose **Depoyu indir ve workflow'ları tara**.
4. Select a workflow and event. Inputs declared under `workflow_dispatch.inputs` are rendered automatically.
5. Inspect the plan, review the workflow commands, check the trust confirmation, then run.
6. Download the JSON and Markdown reports before the Colab runtime stops.

The engine source is `verify/colab_actions/colab_actions_runner.py`. The notebook fetches it from the configured Tessera repository/ref and runs a Python syntax check before opening the UI.

## Compatibility

| GitHub Actions feature | Colab behavior |
|---|---|
| Workflow discovery | Reads `.yml` and `.yaml` files under `.github/workflows` |
| Events | User selects a declared event; dispatch inputs are rendered dynamically |
| Jobs and `needs` | Executed serially in dependency order |
| Matrix | Basic Cartesian combinations, `include` and `exclude` |
| `if` | Basic comparisons, `&&`, `||`, `! `, `always()`, `success()`, `failure()`, `startsWith()`, `contains()` |
| Expressions | Common `github.*`, `runner.*`, `matrix.*`, `inputs.*`, `env.*`, `steps.*.outputs.*` references |
| `run` | Linux Bash, sh and Python steps |
| `actions/checkout` | Primary workspace checkout and additional repository checkout |
| Local actions | Local composite actions; nested depth is bounded |
| Artifacts | `upload-artifact` / `download-artifact` via local ZIP files for the same Colab run |
| Cache | `actions/cache` is a no-op because the Colab runtime is ephemeral |
| setup actions | `setup-python` checks the currently available Python version; `setup-node` checks for an existing Node binary |
| Reports | JSON and Markdown files saved under `/content/colab-actions-reports` |

This is a deliberately limited compatibility layer, not a complete GitHub Actions implementation. Unsupported Marketplace actions, Docker actions, reusable workflows, services/containers, complex expressions, all path-filter semantics, job-level outputs and remote artifact hosting are not fully implemented. GitHub token permission scopes are not reproduced. A workflow that relies on one of these features may be marked PARTIAL or UNSUPPORTED.

## Tessera workflow interpretation

- `.github/workflows/ci.yml`: its build/test, Detours, no-RTTI, static-analysis and SDK packaging jobs are Windows/MSVC jobs. They are reported as `BLOCKED_PLATFORM` in Colab and are not misreported as passing.
- `.github/workflows/native-hook-fuzz.yml`: requires Windows, MSVC and clang-cl sanitizer runtimes, so it is also blocked on Colab Linux.
- `.github/workflows/project-validation.yml`: is the most suitable workflow for a Linux-based Colab execution, subject to the repository profile and commands being compatible with the current runtime.
- `.github/workflows/import-source.yml`: contains repository mutation/push steps. Do not run it unless the exact source archive and all commands have been reviewed. The Colab runner does not inject a GitHub token into job shells, so authenticated push behavior is not provided.

A `PARTIAL` result means some jobs or steps were blocked/skipped/unsupported. It is not a full CI pass. Only a `PASS` means all selected compatible jobs and steps completed successfully in this Colab run. Even then, it is not evidence for Windows-native behavior.

## Security model

Workflow commands execute as the current Colab user and can read/write files available to that runtime. Colab is not a hardened sandbox. Use only trusted repositories and refs. Do not run untrusted pull requests while a token is available.

The token is read from Colab Secrets and used for repository discovery and Git clone authentication through a temporary askpass helper. The helper file is removed after clone. The token is not placed in notebook source, repository URLs, workflow command arguments, or the environment passed to ordinary steps. Expressions referencing `secrets.*` and credential-like step environment variables are blocked. This reduces accidental exposure but does not make untrusted code safe: notebook/runtime APIs and user-granted Colab secrets remain within the same runtime trust boundary.

The runner does not publish GitHub checks, commit statuses, releases, PR comments, or repository changes. Artifact ZIPs and reports are local to the current Colab session. Long operations remain subject to Colab runtime, CPU, RAM and disk quotas.

## Manual test checklist

- [ ] Open the notebook from the branch containing these files in Google Colab.
- [ ] Run the launcher cell; verify that the engine downloads and `py_compile` succeeds.
- [ ] Connect to a public repository and discover its workflow files.
- [ ] With a Colab Secret, list accessible repositories and branches.
- [ ] Analyze Tessera `ci.yml`; verify that Windows jobs show `BLOCKED_PLATFORM`.
- [ ] Analyze `native-hook-fuzz.yml`; verify that it is blocked on Linux.
- [ ] Use a trusted Linux workflow with a harmless shell step to verify execution, environment variables and step logs.
- [ ] Verify dispatch inputs, matrix expansion, `needs`, `if`, `GITHUB_ENV`, `GITHUB_OUTPUT` and local artifact ZIP handling.
- [ ] Verify timeout/cancel behavior and download both report formats.
- [ ] Do not treat portable Linux results as Windows/MSVC validation.

The final runtime/Colab checklist must be completed in a real Colab session; it is not asserted as passed by a notebook file commit.
