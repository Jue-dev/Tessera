# Issue #6 — CI validation checklist

**Validation branch:** `issue-6/unwind-lifecycle`  
**Validated PR head:** `f4cc4d1715cef026585cf14650659981f891ace4`  
**Evidence:** [CI run #18 / 44561390158](https://github.com/Jue-dev/Tessera/actions/runs/44561390158)  
**Snapshot date:** 2026-11-19

This checklist distinguishes automated evidence from host-level integration obligations. A green CI run is not a proof that every production host follows the admission/drain contract.

## A. Current-head Windows matrix

- [x] x86 Debug configure/build/CTest and SDK staging.
- [x] x86 Release configure/build/CTest and SDK staging.
- [x] x64 Debug configure/build/CTest and SDK staging.
- [x] x64 Release configure/build/CTest and SDK staging.
- [x] All four jobs ran on the exact PR head above.
- [x] No failed jobs; release publication was skipped by its tag-push guard.

Run #44561390158 completed successfully. All eight active jobs passed; the release job was skipped as expected. SDK artifacts were produced for all four configurations:
- `Tessera-SDK-x86-debug`
- `Tessera-SDK-x86-release`
- `Tessera-SDK-x64-debug`
- `Tessera-SDK-x64-release`

## B. Native x64 unwind and lifecycle regression suite

- [x] Full CTest suite passed in the exact-head Windows matrix.
- [x] Regression tests for PUSH_NONVOL, multi-slot ALLOC_LARGE, SAVE_NONVOL, far SAVE_NONVOL, far SAVE_XMM128, PUSH_MACHFRAME, SET_FPREG, and SAVE_XMM128.
- [x] Malformed/unsupported metadata rejection: handler/chained records, unsupported version/opcode, unmappable instruction-interior offsets, ENDBR boundary, source-function bounds, and unreadable extra slots.
- [x] Unregister-failure retry regression.
- [x] DLL fixture / admission-gate / active-detour drain / detach / FreeLibrary ordering regression test ran as part of CTest.
- [ ] Independently inspect the detailed per-test logs and verify every test name/result beyond the aggregate CTest evidence.

## C. Sustained sanitizer fuzz

- [x] Deterministic fuzz/smoke target passed in CI quality gate.
- [ ] Current-head Windows x64 Clang libFuzzer + ASan/UBSan bounded 300-second campaign.
- [ ] Inspect uploaded corpus/crash artifact and retain any new reproducer as a regression seed.

The sustained campaign is separate and manual-only in `.github/workflows/native-hook-fuzz.yml`. The previous five-minute campaign was on an earlier SHA and does not validate this head.

## D. Full quality gates

- [x] `/GR-` no-RTTI build, tests, fuzz smoke, benchmark smoke, and SDK install/package check.
- [x] Live Microsoft Detours integration x86.
- [x] Live Microsoft Detours integration x64.
- [x] MSVC `/analyze` build and tests.
- [x] SDK packaging/staging matrix.
- [x] Confirmed release publication skipped; no release was created.

Evidence: CI run #44561390158, exact validated head.

## E. Host lifecycle acceptance

- [x] Test fixture demonstrates admission gate blocks stop while an active detour callback is held.
- [x] Test fixture drains callback, detaches hook, unloads detour DLL, and calls original target afterward.
- [ ] Independent real-application host integration: prove the host gates all direct target calls, callback entries, and raw/escaped trampoline pointers; this is outside what the fixture can establish.
- [ ] Document and enforce that `Hook` destruction/move is externally synchronized and explicit `remove()` is checked before unloading callback code.
- [ ] Host thread-creation policy: a Toolhelp snapshot is not a thread-creation barrier; admission gate/quiescence is required.

The fixture test passed on the validated CI head. This does not replace integration with the actual host application's call paths.

## F. Failure-path audit

- [x] Static ownership/control-flow review: unpublished state is owned by `unique_ptr`; failures before patch publication release temporary resources.
- [x] `RtlAddFunctionTable` failure path is before target patching and only marks registration after success.
- [x] Patch transaction rollback tests, including protection failure, flush rollback, fatal rollback, and success, passed in CI.
- [x] Unregister-failure retry test passed in CI.
- [x] Additional source-level audit reviewed HookCore lease/install/remove/release/destructor paths, native attach/detach ownership, unwind metadata parsing/registration, thread-suspension RAII, and patch-write rollback transaction. No clear defect was identified in those reviewed paths.
- [ ] Independent reviewer audit of every failure edge, including registry ownership, target bytes, page protection, unwind registration, token validity, and retryability.
- [ ] Deterministic Windows API failure injection for allocation, registration, protection, and cache flush; current static review/test seams do not inject every system API failure.

## G. Workflow and quota policy

- [x] CI validation is manual-only for the PR branch; no PR/schedule triggers.
- [x] Fuzz workflow is manual-only with bounded campaign choices.
- [x] `pr-smoke.yml` preserved but manual-only (`workflow_dispatch`).
- [x] Release job guarded to a version-tag push.
- [x] No merge, release, or tag action performed.
- [x] Avoid redundant Actions runs: current-head Windows matrix and quality gates are green; do not rerun them without a specific code change or need.

## Additional source review note

Reviewed the lifecycle core and backend source after the current-head CI run. The checked paths preserve ownership until successful detach; unregister failure reinstalls the patch and retains retry state; thread suspension is RAII-resumed; fatal rollback uncertainty terminates rather than returning an unsafe state. This is a source review by the current assistant, not an independent human review or injected system-API failure test.

## Current conclusion

The current-head Windows CI matrix and quality gates are **PASS**. Issue #6 and PR #7 are **not ready to close/merge** because the sustained current-head sanitizer campaign, independent final failure-path review, and real host integration acceptance remain outstanding. PR #7 remains draft and Issue #6 remains open.

## Next work

1. Obtain an independent reviewer audit of the failure paths; current assistant source review is not a substitute.
2. Run the current-head five-minute fuzz campaign once and inspect artifacts. Workflow dispatch is not exposed through the current GitHub connection, so this must be initiated from the Actions UI.
3. Obtain real host admission/drain/unload acceptance in the consuming application.
4. Produce a final evidence-based report. Do not merge or close Issue #6 without explicit authorization.
