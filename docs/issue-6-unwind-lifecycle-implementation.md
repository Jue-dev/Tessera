# Issue #6 — implementation progress and validation status

This record covers native x86/x64 inline-hook unwind and call-lifecycle safety. The validation checklist is [issue-6-ci-validation-checklist.md](issue-6-ci-validation-checklist.md).

## Implementation

- x64 trampoline unwind metadata is generated and registered before the target patch is published.
- Version-1 unwind operations are validated and mapped only at relocated instruction boundaries. Unsupported handlers/chained records, opcodes, malformed slot streams, non-entry targets, and unsupported prologues fail closed.
- Source runtime-function and unwind data are bounds/readability checked. Stolen prologues may not exceed the source function.
- Targets without unwind records are accepted only for the audited stack-neutral leaf subset.
- Detach/unregister failure restores the target patch and preserves retryable state.
- `Hook::acquire()` supplies a non-copyable, non-movable, thread-affine callable lease. Raw pointers returned by `original()` remain untracked and require host quiescence.
- Regression coverage includes unwind opcode/slot variants, malformed metadata, rollback, unregister retry, and a DLL fixture for admission/drain/detach/unload order.

## Workflow policy

The full `.github/workflows/ci.yml` matrix is configured in this branch for automatic relevant pull-request validation and relevant pushes to `main`, plus manual dispatch. Release publication remains version-tag-only. The focused native-hook fuzz workflow remains manual-only with bounded 60/300/900-second campaigns.

The redundant PR-smoke workflow and obsolete source-archive import workflow were removed from this branch. The PR trigger is a branch change and has not yet been verified by an automatic run; the current base branch does not contain that trigger. The available GitHub connector can read workflow runs but cannot dispatch workflows.

## Current-head test evidence

Validated implementation commit: `313d96f503ac835d602499b7350270d5198d71a0`.

- Windows CI [run #19 / 44566729475](https://github.com/Jue-dev/Tessera/actions/runs/44566729475) passed the x86/x64 Debug/Release matrix, CTest, SDK staging, Detours x86/x64, no-RTTI quality gate, MSVC `/analyze`, and packaging. Release publication skipped as expected.
- x64 Clang libFuzzer + ASan/UBSan [run #24 / 44566681404](https://github.com/Jue-dev/Tessera/actions/runs/44566681404) completed 900 seconds: 14,666,829 executions, 2,651 new units, 978 coverage counters, 1,999 features, and no crash/sanitizer finding.
- Artifact review found 797 corpus files and no crash reproducer files.
- x86 sustained coverage-guided fuzzing was not run. x86 Debug/Release CI, Detours integration, and deterministic fuzz smoke passed.

These runs validate the implementation commit, not subsequent workflow/documentation-only commits.

## Failure-path audit

The reviewed attach path keeps unpublished `NativeHookState` in `unique_ptr` until patch commit, registry insertion, and token ownership transfer. Registry capacity is reserved before target modification. Unwind registration occurs before patch publication and its state flag is set only on success. Recoverable patch failures roll back original bytes and protection; uncertain rollback fails fast. Detach unregister failure reinstalls the patch and retains the token/allocation/registry ownership for retry.

This is source-level review, not deterministic Windows API failure injection. Allocation, protection, cache-flush, and function-table registration failure injection remain incomplete. An independent reviewer audit of every failure edge is also outstanding.

## Host integration contract

The fixture proves a controlled admission gate, active callback drain, successful detach, DLL unload, and original-target call. It does not prove that the real application gates all target calls, callbacks, or raw/escaped trampoline pointers. The host must stop admitting calls, drain every use, check successful `remove()`, and only then unload detour code. A Toolhelp thread snapshot is not a thread-creation barrier.

## Remaining acceptance gates

- [ ] Independent review of all failure edges and rollback ownership.
- [ ] Deterministic Windows API failure injection for allocation, function-table registration, protection, and cache-flush failures.
- [ ] Real host admission/drain/unload integration.
- [ ] Fresh CI for workflow/documentation commits in this branch.

## Status

The implementation commit's Windows CI matrix, full quality gates, and sustained 900-second x64 sanitizer campaign are **PASS**. PR #7 remains draft and Issue #6 remains open. No merge or release has been performed.

Do not close Issue #6 until the remaining acceptance gates are completed or explicitly accepted.
