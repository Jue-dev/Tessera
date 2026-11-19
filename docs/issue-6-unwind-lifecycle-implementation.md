# Issue #6 — implementation progress and validation status

This is the implementation record for native x86/x64 inline-hook unwind and
call-lifecycle safety. The separate, executable validation checklist is
[issue-6-ci-validation-checklist.md](issue-6-ci-validation-checklist.md).
The PR stays in draft and Issue #6 stays open until every required gate has
current-head evidence.

## CI / Actions usage policy

Pull-request validation is intentionally one-shot. A normal code commit on
this draft PR must not start a Windows matrix or fuzz campaign. The dedicated
`.github/workflows/issue-6-acceptance.yml` runs the four-way Windows matrix
only when the PR is explicitly marked ready for review (or manually dispatched
after the workflow exists on the default branch). It has no synchronize trigger.
The short `pr-smoke.yml` and focused `native-hook-fuzz.yml` workflows are
manual-only. The five-minute fuzz campaign is a separate deliberate dispatch.
The full SDK/quality workflow runs on relevant main-branch pushes, tags, or
manual dispatch; its weekly schedule is disabled.

This keeps PR iterations cheap, avoids duplicate smoke/fuzz workflows, and
makes expensive validation deliberate. Keep the PR draft while code changes
are in progress; mark it ready only once the current commit is ready for the
Windows matrix. Do not treat skipped or unstarted checks as passing.

## Progress summary

| Work item | Status | Evidence / next step |
|---|---|---|
| x64 dynamic trampoline unwind registration | [x] Implemented | Stable RUNTIME_FUNCTION and UNWIND_INFO storage; register before publishing the target patch |
| Version-1 unwind translation | [x] Implemented | Supported code offsets mapped through exact relocated instruction boundaries; multi-slot payloads copied |
| Fail-closed unwind validation | [x] Implemented | Unsupported version/opcodes, handler/chained records, malformed slot streams, non-entry targets, and unmappable offsets rejected |
| Source metadata memory bounds | [x] Implemented | Validate runtime-function record, unwind header, and full unwind-code array are in committed readable memory |
| Source function bounds | [x] Implemented | Reject stolen prologue ranges that extend past the registered source function before writing target bytes |
| No-source-record policy | [x] Implemented | Only audited stack-neutral leaf subset accepted; unsupported dynamic prologues rejected |
| Detach/unregister retry | [x] Implemented | On unregister failure, reinstate the patch and retain registration, allocation, registry ownership, and retryable token |
| Explicit callable lease API | [x] Implemented | Hook::acquire(), get(), and target(); non-copyable, non-movable, thread-affine |
| Expanded x64 unwind regression tests | [x] Added; CI pending | ALLOC_LARGE, PUSH_NONVOL, SAVE_NONVOL, SET_FPREG, SAVE_XMM128, function-boundary rejection, and unreadable-slot rejection |
| x86/x64 preprocessor separation | [x] Corrected; CI pending | Balanced x64-only guards; the x86 matrix must confirm x64 fixture exclusion |
| Windows x86/x64 Debug/Release on current head | [ ] Deferred | Actions quota unavailable; see the separate CI checklist |
| Five-minute Clang libFuzzer + ASan/UBSan on current head | [ ] Deferred | Previous run passed on an earlier commit, not this head |
| Full /GR-, Detours, /analyze, SDK packaging gates | [ ] Deferred | Must run after PR Smoke returns green |
| Host admission/drain/module-unload acceptance | [ ] Remaining | Verify stop-admission → drain all target/detour/raw calls → remove → unload |
| Allocation and RtlAddFunctionTable failure injection | [ ] Remaining | Add deterministic injection or document a rigorous proof for the affected cleanup paths |
| Final independent audit | [ ] Remaining | Re-check bytes, page protections, token, registry, unwind registration, and lifetime on every failure edge |

## Implementation contract

### x64 unwind metadata

Each x64 trampoline owns its dynamic function-table entry and version-1 unwind
record in its near allocation. The table is registered after the generated
code/metadata are finalized and before the target patch is made visible.

For an existing source RUNTIME_FUNCTION, the hook target must be the
function entry. The backend validates the source record and unwind bytes before
reading them, checks the stolen range against the source function bounds, and
maps supported CodeOffset values only when they coincide with relocated
instruction boundaries. A CodeOffset at or before the preserved ENDBR prefix is
rejected because the landing pad cannot complete an unwind operation. Extra
slots are retained. Unsupported versions,
opcodes, malformed records, exception/termination handler flags, chained
records, and non-mappable offsets fail closed before target modification.

When no source runtime-function record exists, only the audited stack-neutral
leaf subset is accepted. Tessera does not synthesize unwind semantics for
stack-changing or non-leaf dynamic code. x86 does not use x64
RUNTIME_FUNCTION tables.

Detach restores the target and checks the supported backend coordination path
before unregistering the dynamic table. On unregister failure, the hook patch
is reinstated and the token, table, registry ownership, and allocation remain
available for retry. Memory is not freed while Windows may still consult it.

### Callable lease and host ownership

Hook::acquire() returns a non-copyable, non-movable, thread-affine scoped
lease. get() exposes the current original/trampoline callable; target()
exposes the target entry so a caller can acquire the lease before entering the
detour. The Hook must outlive its lease, and the lease must be destroyed on the
acquiring thread.

The lease cannot track pointers that escape its scope, direct target calls
made without acquiring it, or any external call path not controlled by the
host. original() remains a raw non-owning pointer for compatibility.
Therefore the host must stop admitting calls, drain every target call,
callback, and raw/escaped trampoline call, verify successful remove(), and
only then destroy hook state or unload the detour module. A Toolhelp thread
snapshot is not a thread-creation barrier and is not a replacement for this
protocol.

## Validation evidence

- PR Smoke #96 passed x64 Release, x86 Release, x64 Debug, and x86 Debug on
  commit ad8a378d994522d7bebabde5a70d9330298fac33.
- The x64 Release deterministic native-hook smoke passed in that same run.
- Native Hook Coverage-Guided Fuzz run #8 completed the bounded Windows x64
  clang-cl libFuzzer + ASan/UBSan campaign successfully on that same earlier
  commit; artifact native-hook-libfuzzer-8 was uploaded.
- The expanded unwind tests, readable-metadata checks, function-bound checks,
  and x86 preprocessor-guard correction were added after that green commit.
  They have not been validated on the current head.
- The repository's Actions allowance is currently unavailable. Queued,
  skipped, cancelled, runner-less, or unsuccessful workflow records are not
  evidence of a passing test.
- The current exact-head test gates and expected evidence are recorded in
  docs/issue-6-ci-validation-checklist.md.

## Definition of done

Do not close Issue #6 until the current-head PR Smoke and fuzz validations pass,
the full quality gates are reviewed, the host-side admission/module-unload
contract is validated, failure paths have sufficient deterministic coverage or
a rigorous documented proof, and the final safety audit is complete. This PR
remains draft; no merge or release is performed here.
