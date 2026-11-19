# Issue #6 — CI validation checklist

**Validated implementation commit:** `313d96f503ac835d602499b7350270d5198d71a0`  
**Windows CI evidence:** [run #19 / 44566729475](https://github.com/Jue-dev/Tessera/actions/runs/44566729475)  
**Coverage-guided fuzz evidence:** [run #24 / 44566681404](https://github.com/Jue-dev/Tessera/actions/runs/44566681404)  
**Snapshot date:** 2026-11-19

The implementation commit above passed the Windows matrix, quality gates, and sustained x64 fuzzing. Workflow/documentation cleanup commits after that code checkpoint have not been rerun in this environment. This checklist distinguishes CI evidence from host-level integration obligations.

## A. Current-head Windows matrix (implementation commit 313d96f)

- [x] x86 Debug configure/build/CTest and SDK staging.
- [x] x86 Release configure/build/CTest and SDK staging.
- [x] x64 Debug configure/build/CTest and SDK staging.
- [x] x64 Release configure/build/CTest and SDK staging.
- [x] No failed jobs; release publication skipped by the tag-push guard.

Run #44566729475 completed successfully. All eight active jobs passed. SDK artifacts were produced for all four configurations:
- `Tessera-SDK-x86-debug`
- `Tessera-SDK-x86-release`
- `Tessera-SDK-x64-debug`
- `Tessera-SDK-x64-release`

## B. Native x64 unwind and lifecycle regression suite

- [x] Full CTest suite passed.
- [x] Regression tests for PUSH_NONVOL, multi-slot ALLOC_LARGE, SAVE_NONVOL, far SAVE_NONVOL, far SAVE_XMM128, PUSH_MACHFRAME, SET_FPREG, and SAVE_XMM128.
- [x] Malformed/unsupported metadata rejection: handler/chained records, unsupported version/opcode, unmappable instruction-interior offsets, ENDBR boundary, source-function bounds, and unreadable extra slots.
- [x] Unregister-failure retry regression.
- [x] DLL fixture admission-gate / active-detour drain / detach / FreeLibrary ordering test ran.
- [ ] Independently inspect detailed per-test logs beyond aggregate CTest evidence.

## C. Sustained sanitizer fuzz

- [x] Deterministic fuzz/smoke target passed in CI quality gate.
- [x] Current-head Windows x64 Clang libFuzzer + ASan/UBSan campaign completed for **900 seconds (15 minutes)**, exceeding the 300-second gate.
- [x] Run #24 used exact implementation commit `313d96f503ac835d602499b7350270d5198d71a0`.
- [x] Fuzzer reported 14,666,829 executions, 2,651 new units, 978 coverage counters, and 1,999 features.
- [x] Artifact reviewed: 797 corpus files; no crash/sanitizer reproducer files.
- [x] No crash or sanitizer failure reported.
- [ ] Sustained x86 coverage-guided fuzzing is optional follow-up. x86 Debug/Release CI, Detours integration, and deterministic smoke passed; sustained fuzz targets x64.

## D. Full quality gates

- [x] `/GR-` no-RTTI build, tests, fuzz smoke, benchmark smoke, and SDK install/package check.
- [x] Microsoft Detours integration x86.
- [x] Microsoft Detours integration x64.
- [x] MSVC `/analyze` build and tests.
- [x] SDK packaging/staging matrix.
- [x] Release publication skipped; no release created.

Evidence: CI run #44566729475 on the implementation commit.

## E. Host lifecycle acceptance

- [x] Fixture demonstrates admission gate blocks stop while an active detour callback is held.
- [x] Fixture drains callback, detaches hook, unloads detour DLL, and calls original target afterward.
- [ ] Real-application host integration: prove all direct target calls, callback entries, and raw/escaped trampoline pointers are gated and drained.
- [ ] Host enforces external synchronization for Hook destruction/move and checks explicit `remove()` before unloading callback code.
- [ ] Host thread-creation policy accounts for Toolhelp snapshot not being a thread-creation barrier.

The fixture is CI evidence, not proof of the application's actual call paths.

## F. Failure-path audit

- [x] Static ownership/control-flow review of unpublished attach state and rollback.
- [x] `RtlAddFunctionTable` registration occurs before patch publication; registration state is set only after success.
- [x] Patch transaction rollback tests for protection failure, flush rollback, fatal rollback, and success passed.
- [x] Unregister-failure retry test passed.
- [x] Source-level review of HookCore leases/lifecycle, native attach/detach ownership, unwind parsing/registration, thread-suspension RAII, and patch-write rollback found no clear defect in reviewed paths.
- [ ] Independent reviewer audit of every failure edge, including registry ownership, target bytes, page protection, unwind registration, token validity, and retryability.
- [ ] Deterministic Windows API failure injection for allocation, registration, protection, and cache-flush failures. Current tests do not inject every system API failure.

## G. Workflow policy

- [x] Fuzz workflow remains manual-only and bounded (60/300/900 seconds).
- [x] Release job remains restricted to version-tag pushes.
- [x] Removed obsolete source-archive import workflow.
- [x] Removed redundant manual PR-smoke workflow; the full CI workflow now defines a PR trigger in this branch.
- [ ] Verify the automatic PR CI trigger on the updated branch. The GitHub connector available in this session can inspect runs but cannot dispatch workflows; this PR branch's workflow trigger is not yet present on base `main`, so it cannot be triggered from this session.
- [x] No merge, release, or tag action performed.

## Current conclusion

The implementation commit's Windows matrix, full quality gates, and 900-second x64 sanitizer campaign are **PASS**. Remaining acceptance work is independent failure-path review, real host admission/drain/unload acceptance, and deterministic Windows API failure injection.

The later workflow/documentation-only branch changes need a fresh CI run before merge. PR #7 remains draft and Issue #6 remains open. Do not merge or close without explicit authorization.
