# Issue #6 — CI validation checklist

**Validation target:** current PR branch `issue-6/unwind-lifecycle`. The last source/test commit is followed by documentation and workflow-only commits. The current exact head must be checked when dispatching; no result from an earlier SHA counts for the current head.

This checklist is intentionally separate from the implementation notes. Do not
mark an item complete until the corresponding job/test has passed on the
current PR head commit. The latest source changes are not considered validated until this checklist
has been run with Actions available again. Workflows are deliberately manual
for PR validation so each iteration does not consume Actions automatically.

## A. PR Smoke — required on the latest head

- [ ] x64 Debug: configure, compile, and all CTest suites pass.
- [ ] x64 Release: configure, compile, all CTest suites, and deterministic
  native-hook fuzz smoke pass.
- [ ] x86 Debug: configure, compile, and all CTest suites pass. Confirm that
  x64-only unwind fixtures are correctly excluded from x86 compilation.
- [ ] x86 Release: configure, compile, and all CTest suites pass.
- [ ] No warnings promoted to errors, test hangs, or flaky thread lifecycle
  failures.

Primary workflow: `.github/workflows/ci.yml`. It is manual-dispatch
capable and has no PR/schedule trigger. Select the PR branch and dispatch once
for the full Windows x86/x64 Debug/Release matrix, quality gates, and SDK
packaging. Expected evidence: successful required jobs on the exact commit SHA.
The release job is tag-only; dispatching on this branch must not publish.

## B. x64 unwind runtime correctness — all tests below

Run the complete `[hook][native][unwind]` test group, not just the new cases.
Also run the `[hook][native][lifecycle][module]` group for real DLL unload ordering.

- [ ] Existing `UWOP_ALLOC_SMALL` SEH test: exception raised inside relocated
  prologue is dispatched and unwound successfully.
- [ ] `UWOP_PUSH_NONVOL`: two pushed nonvolatile registers are both restored
  when unwinding through the trampoline.
- [ ] `UWOP_ALLOC_LARGE` with OpInfo=1: three-slot metadata is copied and
  `RtlVirtualUnwind` restores RSP to the caller frame.
- [ ] `UWOP_SAVE_NONVOL`: two-slot metadata restores the saved GPR value.
- [ ] `UWOP_SAVE_NONVOL_FAR`: three-slot metadata restores a saved GPR at a
  far stack offset.
- [ ] `UWOP_SAVE_XMM128_FAR`: three-slot metadata restores the saved XMM value
  at a far stack offset.
- [ ] `UWOP_PUSH_MACHFRAME`: OpInfo=0 and OpInfo=1 reconstruct the simulated
  machine frame correctly.
- [ ] `UWOP_ALLOC_LARGE` with OpInfo=0 plus `UWOP_SET_FPREG` and
  `UWOP_PUSH_NONVOL`: frame-pointer based unwind restores RBP and RSP.
- [ ] `UWOP_SAVE_XMM128`: the saved nonvolatile XMM register is restored.
- [ ] Handler and chained records are rejected before target bytes change.
- [ ] An unwind CodeOffset inside a relocated instruction is rejected before
  target bytes change.
- [ ] An unwind CodeOffset equal to the preserved ENDBR64 prefix length is
  rejected; ENDBR cannot complete a stack-changing unwind operation.
- [ ] Version-2 unwind metadata and reserved version-1 opcodes fail closed
  before target bytes change (covered in the malformed-metadata regression case).
- [ ] A stolen patch that crosses the source function end is rejected before
  target bytes change.
- [ ] A truncated/unreadable extra unwind-code slot is rejected without an
  access violation and without changing target bytes.
- [ ] Unregister failure reinstates the patch and retains a retryable token;
  a subsequent retry removes the table and releases resources.

Relevant regression tests (exact names):
- `Native x64 trampoline unwinds multiple pushed nonvolatile registers`
- `Native x64 trampoline maps multi-slot UWOP_ALLOC_LARGE for virtual unwind`
- `Native x64 trampoline maps multi-slot UWOP_SAVE_NONVOL for virtual unwind`
- `Native x64 trampoline maps far UWOP_SAVE_NONVOL and UWOP_ALLOC_LARGE`
- `Native x64 trampoline maps far UWOP_SAVE_XMM128 and UWOP_ALLOC_LARGE`
- `Native x64 trampoline maps UWOP_PUSH_MACHFRAME with and without error code`
- `Native x64 unwind rejects unsupported, malformed, and prefix-boundary source metadata` (EHANDLER, CHAININFO, instruction-interior offset, ENDBR boundary, version 2, reserved opcode)
- `Native x64 trampoline maps ALLOC_LARGE and SET_FPREG together`
- `Native x64 trampoline restores a saved nonvolatile XMM register`
- `Native x64 unwind rejects a stolen patch that crosses the source function end`
- `Native x64 unwind rejects an unreadable extra unwind-code slot without faulting`
- `Native x64 trampoline remaps unwind offsets and unwinds an exception in relocated prologue`

## C. Coverage-guided fuzz — required on the latest head

- [ ] Windows x64 clang-cl toolchain verification succeeds.
- [ ] Instrumented production objects and native-hook fuzzer build with
  libFuzzer + ASan + UBSan.
- [ ] Bounded campaign completes its full configured five minutes with exit
  code 0 and no ASan/UBSan finding, crash, timeout, or OOM.
- [ ] Final statistics are present in the job log.
- [ ] Corpus/crash artifact uploads successfully; inspect the artifact and
  retain any new reproducer as a checked-in regression seed.

Run `.github/workflows/native-hook-fuzz.yml` manually from the Actions UI
with the PR branch selected and `campaign_seconds=300` after allowance is
available. The workflow has no push, PR, or schedule trigger.
Expected evidence: successful “Run bounded coverage-guided campaign” and
“Upload fuzz corpus and crash artifacts” steps for the exact commit SHA.

## D. Full quality gate — run after PR Smoke is green

- [ ] Full x86/x64 Debug/Release CTest and SDK packaging matrix passes.
- [ ] `/GR-` no-RTTI build, all tests, fuzz smoke, benchmark smoke, and
  single-library SDK install check pass.
- [ ] Live Microsoft Detours integration passes on x86 and x64.
- [ ] MSVC `/analyze` build and CTest pass.
- [ ] No unintended release/publish job is started from this branch.

Workflow: `.github/workflows/ci.yml` (source-path-filtered main push or manual
only; scheduled runs are disabled). Inspect every job and do not publish a release.

## E. Host-lifecycle acceptance — review/test before closing Issue #6

- [ ] Application admission gate blocks new target calls before install and
  before detach.
- [ ] The host drains direct target calls, active detour callbacks, and every
  raw/escaped trampoline call, not only calls made through `Hook::acquire()`.
- [ ] Detach succeeds before hook state or the detour module is destroyed.
- [ ] `Native hook host admission drains active detours before unloading the detour module`
  passes on x86 and x64. The regression test is implemented; Windows execution
  is pending. It loads a real DLL detour, holds a callback active,
  proves the host admission gate cannot close early, drains the call, removes
  the hook, calls `FreeLibrary`, and verifies the original target still runs.
- [ ] Concurrent operations on the same `Hook` object are externally
  synchronized; no claim is made that the wrapper is itself thread-safe.

## F. Failure-path audit

- [ ] Source `RUNTIME_FUNCTION` and `UNWIND_INFO` reads are bounded to
  committed readable memory.
- [ ] Unwind slot parsing/serialization uses bounded byte spans; no one-element
  trailing array is indexed beyond its declared extent.
- [ ] Source function bounds are checked before the target is patched.
- [x] Allocation failure path statically audited: temporary state remains in
  a `unique_ptr`; allocation/relocation failures occur before target writes,
  and a partially built trampoline is freed by state destruction.
- [x] `RtlAddFunctionTable` failure path statically audited: the registered
  flag is set only after success; failure returns before thread suspension or
  target patching, and the unpublished allocation is freed by state destruction.
- [ ] `RtlDeleteFunctionTable` failure remains retryable and does not free
  memory still registered with Windows. Regression test exists:
  `Native x64 unwind unregister failure restores the patch and keeps the token retryable`.
- [ ] Patch-write failure rollback preserves original bytes and page protection;
  uncertain rollback remains fail-fast. Deterministic `FakePatchWriteOps`
  tests cover protection failure, flush rollback, fatal rollback, and success.

## Current execution state

- Actions audit snapshot (2026-11-19): the previously inspected PR head
  `a7a83f8485a4da27c83b49627554467ad9eedf93` had no workflow runs or status
  contexts attached to that exact SHA. Older PR-triggered runs were skipped or
  failed on earlier SHAs and are not evidence for the current head.
- The CI workflow's `publish-sdk-bundle` job is now guarded by both
  `github.event_name == 'push'` and a `refs/tags/v*` ref. Manual dispatches,
  including dispatches against a tag, must not assemble or publish release
  artifacts. Keep the release gate tag-push-only.


- Real shared-library fixture and DLL unload-order test are now part of the
  Windows test executable; the x86 export fallback and DLL basename checks
  were source-reviewed. This test is added, not yet runtime-validated.
- `UnwindCode[1]` trailing-array indexing was removed from production and test
  metadata representations; slots are now copied through bounded byte spans.
  Current-head compilation and runtime checks are still pending.

- Last known green PR Smoke: run #96 on commit
  `ad8a378d994522d7bebabde5a70d9330298fac33`.
- Last known green five-minute fuzz campaign: run #8 on commit
  `ad8a378d994522d7bebabde5a70d9330298fac33`, with uploaded artifact
  `native-hook-libfuzzer-8`.
- Additional unwind tests and source-metadata bounds checks were added after
  that green commit. They are **not yet validated** on the current head.
- Actions validation is deferred because the repository's available Actions
  allowance is exhausted. Do not infer success from queued, skipped, cancelled,
  or runner-less workflow records.

After Actions allowance is restored, dispatch `ci.yml` once with the PR branch
selected for full validation. Dispatch `native-hook-fuzz.yml` only if the
five-minute sanitizer campaign is still required. Both are manual-only; commits
do not start jobs. Avoid duplicate dispatches.
Current PR head and checklist progress must be refreshed when Actions becomes
available. Keep Issue #6 open until sections A–F have evidence or a remaining
item is explicitly resolved with a documented technical justification.
