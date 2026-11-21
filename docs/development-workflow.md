# Development workflow

## Branch and workflow roles

- main is the stable integration and release branch.
- Source/build/verification changes targeting or pushed to main run .github/workflows/ci.yml.
- Quality checks (format, clang-tidy, sanitizers, coverage, CodeQL, and Markdown links) live in .github/workflows/quality.yml.
- Eight continuous fuzz targets and native-hook x86/x64 campaigns live in .github/workflows/fuzz.yml.
- Version tags v*.*.* and manual dispatch run .github/workflows/release.yml.

The lifecycle is consolidated to four workflows. Elevated CodeQL security-events: write permission is scoped to the CodeQL job. CI and quality runs on main are not canceled by newer commits; pull-request runs may be superseded. Release runs are never canceled.

## Shared CI scripts

The former per-action script folders are consolidated into five task-oriented entry points:

| Script | Tasks |
| --- | --- |
| .github/scripts/ci-build.ps1 | configure, preset, detours, detours-integration |
| .github/scripts/ci-verify.ps1 | fuzz-bench, decoder-oracle, examples |
| .github/scripts/ci-sdk.ps1 | package-bundle, package-release, checksum, validate, consumer |
| .github/scripts/ci-windows-mock.sh | Linux normal and ASan/UBSan Windows-mock runs |
| .github/scripts/fuzz-native-hook.ps1 | setup, build, run for x64/x86 |

The scripts are CI-only helpers and are not included in the core SDK. Workflow invocations and task parameters are maintained with these files.

## Validation matrix

| Workflow/event | Validation |
| --- | --- |
| Relevant PR or push to main | MSVC x64/x86 Debug/Release, CTest, Detours x64/x86, reduced/no-RTTI configurations, Linux portable foundation build, windows_mock, decoder oracle, installed SDK consumer, fuzz/benchmark/example smoke |
| Quality PR/push/manual/schedule | clang-format, clang-tidy, ASan+UBSan, TSan, LLVM coverage, CodeQL, Markdown link check |
| Fuzz PR/manual/schedule | Eight MSVC fuzz targets and separate native-hook x64 libFuzzer / x86 MSVC Fuzzer campaigns |
| Release tag or dispatch | x86/x64 Debug/Release SDK export, standalone consumer, archive/checksum validation, GitHub Release assets |

## Final validation

After implementation, run scripts/run-final-validation.ps1 from a Windows PowerShell session with MSVC and Ninja. Include -RunFuzz and -RunDecoderOracle for the extended checks. The optional benchmark preset produces five executables and machine-readable --json metrics. Standalone corpus replay uses the same LLVMFuzzerTestOneInput callbacks as coverage-guided builds but does not replace sustained fuzzing.

## Architecture boundaries

Preserve public API signatures under include/tessera/** and compatibility decisions in ADR 0001–0003. Internal helpers belong under src/**; tests and synthetic fixtures belong under verify/**. Native inline-hook lifecycle and implementation limits are defined by ADR 0002. Component boundaries are defined by ADR 0003. See safety-and-boundaries.md for JSON, memory-write, PE parsing, and decoder contracts.
