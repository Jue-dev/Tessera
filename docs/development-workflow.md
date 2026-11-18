# Development and CI workflow

## Branch roles

- `main` is the stable integration and release branch. Changes that affect source code, build configuration, dependencies, examples, scripts, tests, or workflow definitions receive automatic full CI validation.
- `develop` is the shared development branch. Pushes to it do not start CI automatically; run the full workflow manually when a meaningful checkpoint is ready.
- Short-lived `feature/*` branches are optional. Create them from `develop`, then merge them back into `develop` after review.

## Validation behavior

| Event | Validation |
| --- | --- |
| Relevant change pushed to `main` | Full Windows CI: x86/x64, Debug/Release, tests, Detours integration, packaging and MSVC analysis |
| Documentation-only change pushed to `main` | No automatic CI run |
| Pull Request targeting `main` with relevant changes | x64 Debug build and CTest smoke run |
| Push to `develop` or `feature/*` | No automatic CI run |
| Manual run from Actions | Full CI on the branch selected in the workflow branch picker |
| Weekly schedule or `v*` tag | Existing full validation / release flow |

The automatic path allowlist covers CMake configuration, `cmake/`, `include/`, `src/`, `verify/`, `examples/`, `scripts/`, dependency manifests, `.clang-tidy`, and GitHub workflow files. Paths such as `docs/**`, `README.md`, and other prose-only files are intentionally not included. A commit containing both documentation and at least one allowlisted file still starts CI.

## Normal development cycle

1. Make day-to-day changes on `develop` (or on a short-lived feature branch based on it).
2. When a checkpoint is ready, open **Actions → Tessera CI & SDK Release → Run workflow** and choose `develop` in the branch selector. This runs the full Windows validation against that branch.
3. Once the development branch is ready, open a Pull Request from `develop` to `main`. The lightweight x64 PR smoke test runs automatically when relevant files changed.
4. Merge only after the PR check is successful. The merge commit on `main` then starts the full CI pipeline automatically when it contains relevant paths.

## Notes

- The full CI workflow remains manually runnable from other branches; its `workflow_dispatch` entry is deliberately not restricted to `main`.
- The weekly run remains as a backstop, and version tags retain the existing release behavior.
- Path filters decide whether a workflow starts; they do not replace build or test coverage. Update the allowlist when adding a new top-level build input or source directory.
