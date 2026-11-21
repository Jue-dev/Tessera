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

The CI path allowlist covers CMake configuration, `cmake/`, `include/`, `src/`, `verify/`, `examples/`, `scripts/`, dependency manifests, `.clang-tidy`, and GitHub workflow files. Small PowerShell CI helpers are grouped by responsibility: `detours.ps1` handles architecture-specific Detours build/verification, and `configure.ps1` handles no-RTTI/reduced configurations. Prose-only documentation changes do not start CI. A commit containing documentation and an allowlisted input still starts CI.

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


## Build presets and optional validation

Use the checked-in presets from a Visual Studio Developer PowerShell/Command Prompt with the matching architecture environment:

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure
```

Optional configure/build/test presets are available without changing the default SDK build:

- `x64-analyze`: MSVC static analysis.
- `x64-bench`: scanner, instruction-decoder, PE, JSON, and RTTI-discovery benchmarks; CTest runs all tests plus benchmark smoke checks.
- `x64-fuzz-smoke`: standalone fuzz harnesses; CTest replays all checked-in corpora through the shared `LLVMFuzzerTestOneInput` entry points.

The benchmark executables are `tessera_bench`, `tessera_decoder_bench`, `tessera_pe_bench`, `tessera_json_bench`, and `tessera_rtti_discovery_bench`. The fuzz-smoke preset covers `pattern`, `pe`, `json`, `profile_json`, `python_bridge`, `scanner`, `rtti_discovery`, and (on Windows) `native_hook`.

The independent decoder differential job builds `verify/tests/decoder_oracle/decoder_probe.cpp` and compares instruction boundaries with pinned test-only `iced-x86==1.21.0` using `verify/tests/decoder_oracle/compare_iced.py`. It is enabled by `TESSERA_ENABLE_DECODER_ORACLE=ON` and is not a runtime or SDK dependency. The decoder's supported subset and explicit rejection boundaries are documented in [the native decoder envelope](native-instruction-decoder-envelope.md).

## Technical notes

- [JSON validation and ownership boundaries](json-validation-boundaries.md): profile/target JSON domain ownership and the shared private field readers.
- [Memory write protection recovery](memory-write-recovery.md): pending protection-restore ownership across `MemoryWriter` and `Patch`.
- [Native x86/x64 decoder envelope](native-instruction-decoder-envelope.md): bounded decode metadata and stricter relocation constraints.

## Architecture constraints and repository map

- Preserve public API signatures under `include/tessera/**`; implementation-only helpers belong under `src/**`.
- Keep `core` and `profiling` as compiled targets and keep Python bridge implementation in the `rtti` target.
- Native inline-hook changes must preserve the safety, unwind, thread-suspension, and lifecycle contract in [ADR 0002](adr/0002-native-inline-hook-safety-contract.md).
- Component dependencies and source-splitting constraints are recorded in [ADR 0003](adr/0003-core-profiling-and-rtti-boundaries.md).
- `include/tessera/**`: public SDK headers; `src/**`: private module implementations.
- `verify/tests/**`: deterministic tests and decoder oracle; `verify/fuzz/**`: fuzz harnesses and seed corpora; `verify/bench/**`: opt-in benchmarks.
- Reduced SDK variants install the package and compile a separate `find_package(Tessera CONFIG REQUIRED)` consumer; run the full CI matrix before merging.

## Wave 3 validation commands

The fallback test runner supports deterministic randomization and machine-readable results:

```powershell
ctest --preset x64-debug --output-on-failure
# The CMake test graph also registers a shuffled suite with seed 20261121.
.\scripts\run-final-validation.ps1 -RunFuzz -RunDecoderOracle
```

When Catch2 is unavailable, `test_main.cpp` accepts `--shuffle`, `--seed N`, `--filter substring`, and `--junit path`. When Catch2 is available, CTest uses Catch2's equivalent randomized-order, fixed-seed and JUnit reporter arguments.

All five benchmark executables support `--json`; `verify/bench/validate_bench_json.py` checks their output in CTest when Python is available. Coverage can be enabled on GCC/Clang with `TESSERA_ENABLE_COVERAGE=ON`. CI runs ASan+UBSan and TSan as separate configurations, and CodeQL and continuous fuzz campaigns are scheduled/manual workflows.

Release tags (`v*`) use the SDK packaging job and publish the SDK ZIP with `SHA256SUMS.txt`. See [SECURITY.md](../SECURITY.md) for vulnerability reporting and the native-memory/inline-hook threat model.

