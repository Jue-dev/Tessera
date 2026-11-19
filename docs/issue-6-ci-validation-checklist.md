# Issue #6 — CI validation checklist

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

Primary workflow: `.github/workflows/issue-6-acceptance.yml`. It runs once when
the PR is explicitly marked ready for review, or can be manually dispatched
after the workflow exists on the default branch. It has no synchronize trigger.
The standalone `.github/workflows/pr-smoke.yml` is manual-only for a shorter repeat.
Expected evidence: four successful Windows jobs for the exact commit SHA.

## B. x64 unwind runtime correctness — all tests below

Run the complete `[hook][native][unwind]` test group, not just the new cases.

- [ ] Existing `UWOP_ALLOC_SMALL` SEH test: exception raised inside relocated
  prologue is dispatched and unwound successfully.
- [ ] `UWOP_PUSH_NONVOL`: two pushed nonvolatile registers are both restored
  when unwinding through the trampoline.
- [ ] `UWOP_ALLOC_LARGE` with OpInfo=1: three-slot metadata is copied and
  `RtlVirtualUnwind` restores RSP to the caller frame.
- [ ] `UWOP_SAVE_NONVOL`: two-slot metadata restores the saved GPR value.
- [ ] `UWOP_ALLOC_LARGE` with OpInfo=0 plus `UWOP_SET_FPREG` and
  `UWOP_PUSH_NONVOL`: frame-pointer based unwind restores RBP and RSP.
- [ ] `UWOP_SAVE_XMM128`: the saved nonvolatile XMM register is restored.
- [ ] Handler and chained records are rejected before target bytes change.
- [ ] An unwind CodeOffset inside a relocated instruction is rejected before
  target bytes change.
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

Run `.github/workflows/native-hook-fuzz.yml` manually with
`campaign_seconds=300` after Actions allowance is available. The acceptance
workflow's PR-ready event intentionally skips the sustained campaign to avoid
starting a second long job automatically.
Expected evidence: successful “Run bounded coverage-guided campaign” and
“Upload fuzz corpus and crash artifacts” steps for the exact commit SHA.

## D. Full quality gate — run after PR Smoke is green

- [ ] Full x86/x64 Debug/Release CTest and SDK packaging matrix passes.
- [ ] `/GR-` no-RTTI build, all tests, fuzz smoke, benchmark smoke, and
  single-library SDK install check pass.
- [ ] Live Microsoft Detours integration passes on x86 and x64.
- [ ] MSVC `/analyze` build and CTest pass.
- [ ] No unintended release/publish job is started from this branch.

Workflow: `.github/workflows/ci.yml` (main-push or manual only; automatic
weekly runs are disabled). Inspect every job and do not publish a release.

## E. Host-lifecycle acceptance — review/test before closing Issue #6

- [ ] Application admission gate blocks new target calls before install and
  before detach.
- [ ] The host drains direct target calls, active detour callbacks, and every
  raw/escaped trampoline call, not only calls made through `Hook::acquire()`.
- [ ] Detach succeeds before hook state or the detour module is destroyed.
- [ ] A test or documented integration harness verifies the ordering
  stop-admission → drain → remove → unload.
- [ ] Concurrent operations on the same `Hook` object are externally
  synchronized; no claim is made that the wrapper is itself thread-safe.

## F. Failure-path audit

- [ ] Source `RUNTIME_FUNCTION` and `UNWIND_INFO` reads are bounded to
  committed readable memory.
- [ ] Source function bounds are checked before the target is patched.
- [ ] Allocation failure is tested or the cleanup path is independently
  demonstrated to preserve bytes, page protection, token state, and registry.
- [ ] `RtlAddFunctionTable` failure is tested or the failure path is
  independently audited to leave target bytes untouched and free the
  unpublished allocation.
- [ ] `RtlDeleteFunctionTable` failure remains retryable and does not free
  memory still registered with Windows.
- [ ] Patch-write failure rollback preserves original bytes and page protection;
  uncertain rollback remains fail-fast.

## Current execution state

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

After Actions allowance is restored, mark the PR ready once on the final branch
head to run the four-way Windows matrix. Then manually dispatch the focused fuzz
workflow with a five-minute campaign. Do not push intermediate commits while
the PR is marked ready; new commits do not automatically start another run.
Current PR head and checklist progress must be refreshed when Actions becomes
available. Keep Issue #6 open until sections A–F have evidence or a remaining
item is explicitly resolved with a documented technical justification.
