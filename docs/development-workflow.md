# Development and CI workflow

## Branch roles

- `main` is the stable integration and release branch. Relevant source/build inputs trigger full CI on pushes to main.
- `develop` and feature branches are not automatically validated; use manual dispatch when a checkpoint is ready.
- Pull-request smoke and the sustained native-hook fuzz workflow are preserved but manual-only to conserve Actions usage.

## Validation behavior

| Event | Validation |
| --- | --- |
| Relevant change pushed to `main` | Full Windows CI: x86/x64, Debug/Release, tests, Detours integration, packaging and MSVC analysis |
| Documentation-only change pushed to `main` | No automatic CI run |
| Pull Request | No automatic workflow run |
| Push to `develop` or feature branch | No automatic CI run |
| Manual `Tessera CI & SDK Release` dispatch | Full CI on selected branch; release publication is tag-push-only |
| Manual `Tessera PR Smoke` dispatch | x86/x64 Debug/Release matrix |
| Manual `Native Hook Coverage-Guided Fuzz` dispatch | Bounded 60/300/900-second x64 Clang libFuzzer campaign |

The automatic path allowlist covers CMake configuration, `cmake/`, `include/`, `src/`, `verify/`, `examples/`, `scripts/`, dependency manifests, `.clang-tidy`, and GitHub workflow files. Prose-only documentation changes do not start CI. A commit containing documentation and an allowlisted input still starts CI.

## Final validation

Run the consolidated validation script on Windows with Visual Studio/MSVC, CMake, Ninja, and Clang available:

```powershell
.\scripts\run-final-validation.ps1
```

To include Microsoft Detours v4.0.1, pass its source checkout; the script builds architecture-specific libraries:

```powershell
.\scripts\run-final-validation.ps1 -DetoursRoot .\dependencies\Detours
```

To include the bounded sustained native-hook fuzz campaign:

```powershell
.\scripts\run-final-validation.ps1 -RunFuzz -FuzzSeconds 300
```

The sustained fuzz campaign is opt-in because it takes several minutes and should be run once at the final code checkpoint. Logs and summary are written under `artifacts/final-validation/logs`; fuzz corpus/crash artifacts are under `artifacts/final-validation/native-hook-fuzz`.

## Normal development cycle

1. Make changes on the feature/development branch.
2. Run focused local tests while iterating.
3. At the final checkpoint, run the consolidated script or equivalent GitHub workflows once.
4. Review all logs and artifacts; green tests do not replace real host admission/drain/unload acceptance.
5. Merge only after review and explicit approval.

## Notes

- Full CI remains manually runnable on any selected branch.
- The release job is guarded to version-tag pushes.
- Update path filters when adding new build inputs or top-level source folders.