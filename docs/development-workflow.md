# Development and CI workflow

## Branch roles

- `main` is the stable integration and release branch.
- Pull requests targeting `main` run the full Windows CI matrix when build/source/verification/workflow inputs change.
- Relevant source/build changes pushed to `main` run the same full CI.
- Feature branches can be manually validated using workflow dispatch.
- The sustained native-hook fuzz campaign remains manual-only and bounded.

## Validation behavior

| Event | Validation |
| --- | --- |
| Relevant pull request to `main` | Full Windows CI: x86/x64 Debug/Release, CTest, Detours integration, packaging, MSVC analysis, and SDK artifacts |
| Relevant change pushed to `main` | Full Windows CI |
| Documentation-only change | No automatic CI run unless workflow/config paths are changed |
| Push to feature branch | No automatic CI unless it is part of a PR targeting `main` |
| Manual `Tessera CI & SDK Release` dispatch | Full CI on selected branch; release publication remains tag-push-only |
| Manual `Native Hook Coverage-Guided Fuzz` dispatch | Bounded 60/300/900-second x64 Clang libFuzzer + ASan/UBSan campaign |

The CI path allowlist covers CMake configuration, `cmake/`, `include/`, `src/`, `verify/`, `examples/`, `scripts/`, dependency manifests, `.clang-tidy`, and GitHub workflow files. Prose-only documentation changes do not start CI. A commit containing documentation and an allowlisted input still starts CI.

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

Logs and summary are written under `artifacts/final-validation/logs`; fuzz corpus/crash artifacts are under `artifacts/final-validation/native-hook-fuzz`.

## Normal development cycle

1. Make changes on the feature branch.
2. Run focused local tests while iterating.
3. Open/update a PR; automatic full CI validates relevant changes.
4. At the final checkpoint, run the sustained fuzz campaign and inspect artifacts.
5. Review all logs and artifacts; green tests do not replace real host admission/drain/unload acceptance.
6. Merge only after review and explicit approval.

## Notes

- Full CI remains manually runnable on any selected branch.
- The release job is guarded to version-tag pushes.
- The focused fuzz campaign remains manual because it is intentionally time-bounded and should be run at meaningful checkpoints.
- Update path filters when adding new build inputs or top-level source folders.
