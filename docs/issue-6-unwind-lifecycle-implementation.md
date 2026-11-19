# Issue #6 — implementation progress and validation status

This is the implementation record for native x86/x64 inline-hook unwind and
call-lifecycle safety. The separate, executable validation checklist is
[issue-6-ci-validation-checklist.md](issue-6-ci-validation-checklist.md).
The PR stays in draft and Issue #6 stays open until every required gate has
current-head evidence.

## CI / Actions usage policy

Actions validation is manual-only for this PR. The existing
`.github/workflows/ci.yml` is the full matrix/quality gate and has no PR or
schedule trigger; it can be manually dispatched with the PR branch selected.
The focused `.github/workflows/native-hook-fuzz.yml` is also manual-only,
configurable (60/300/900 seconds), and has no schedule. PR open/ready/
synchronize/reopened and branch-push events do not start jobs. The redundant
PR-smoke workflow was removed.

The main CI workflow runs on relevant main-branch source pushes or manual
dispatch; scheduled runs are disabled and release publication remains tag-only.
The focused fuzzer has a manual dispatch only and uploads its corpus/crash
artifacts.

This reduces duplicate jobs and accidental quota consumption. Keep the PR
draft while implementation is in progress. Do not treat skipped, unstarted,
or older-head checks as passing.

## Progress summary

| Work item | Status | Evidence / next step |
|---|---|---|
| x64 dynamic trampoline unwind registration | [x] Implemented | Stable RUNTIME_FUNCTION and UNWIND_INFO storage; register before publishing the target patch |
| Version-1 unwind translation | [x] Implemented | Supported code offsets mapped through exact relocated instruction boundaries; multi-slot payloads copied via bounded byte spans; offsets at/before preserved ENDBR rejected |
| Fail-closed unwind validation | [x] Implemented | Unsupported version/opcodes, handler/chained records, malformed slot streams, non-entry targets, and unmappable offsets rejected |
| Source metadata memory bounds | [x] Implemented | Validate runtime-function record, four-byte unwind header, and full unwind-code byte span in committed readable memory |
| Source function bounds | [x] Implemented | Reject stolen prologue ranges that extend past the registered source function before writing target bytes |
| No-source-record policy | [x] Implemented | Only audited stack-neutral leaf subset accepted; unsupported dynamic prologues rejected |
| Detach/unregister retry | [x] Implemented; test pending CI | On unregister failure, reinstate the patch and retain registration, allocation, registry ownership, and retryable token; deterministic retry regression test exists |
| Explicit callable lease API | [x] Implemented | Hook::acquire(), get(), and target(); non-copyable, non-movable, thread-affine |
| Actions quota workflow cleanup | [x] Implemented | Removed automatic PR smoke; full CI and sustained fuzz are manual-only; disabled scheduled fuzz; retained tag-only release |
| Expanded x64 unwind regression tests | [x] Added; CI pending | ALLOC_LARGE (near/far), PUSH_NONVOL, SAVE_NONVOL (near/far), SET_FPREG, SAVE_XMM128 (near/far), PUSH_MACHFRAME (both OpInfo values), source bounds/readability, handler/chained/version2/reserved opcode and ENDBR-boundary rejection |
| Unwind slot storage bounds | [x] Corrected; CI pending | Removed `UnwindCode[1]` trailing-array indexing; source and destination slots are read/written using bounded byte spans and `memcpy` |
| x86/x64 preprocessor separation | [x] Corrected; CI pending | Balanced x64-only guards; the x86 matrix must confirm x64 fixture exclusion |
| Windows x86/x64 Debug/Release on current head | [ ] Deferred | Actions quota unavailable; see the separate CI checklist |
| Five-minute Clang libFuzzer + ASan/UBSan on current head | [ ] Deferred | Previous run passed on an earlier commit, not this head |
| Full /GR-, Detours, /analyze, SDK packaging gates | [ ] Deferred | Must run after PR Smoke returns green |
| Host admission/drain/module-unload acceptance | [x] Test added; CI pending | A real detour DLL is held active while the exclusive admission gate is blocked; test releases/drains the callback, removes the hook, unloads the DLL, then verifies the original target still runs. x86 export decoration is resolved explicitly |
| Allocation and RtlAddFunctionTable failure injection | [x] Static failure-path audit | unique_ptr owns temporary state; registration flag is set only after RtlAddFunctionTable succeeds; all failures before target write unwind and release unpublished state. No API-injection harness yet |
| Final independent audit | [ ] Remaining | Re-check bytes, page protections, token, registry, unwind registration, and lifetime on every failure edge |

## Failure-path ownership audit

The backend's attach path is failure-atomic before the first target write:

- The `NativeHookState` remains owned by a local `std::unique_ptr` until the
  patch has committed, the active registry entry has been inserted, and the
  returned `HookToken` takes ownership.
- A failed `VirtualAlloc` returns before any target bytes or target page
  protection are changed. Any later relocation, metadata-validation,
  trampoline-protection, or cache-flush failure returns while the same
  `unique_ptr` still owns the state and allocation.
- `RtlAddFunctionTable` is called before thread suspension and before
  `write_target_bytes`. The `unwind_registered` bit is set only after the API
  returns success. If registration fails, the destructor sees the bit clear
  and releases the unpublished allocation; the target bytes and target page
  protection are untouched.
- Registry capacity is reserved before target modification. The registry
  entry is inserted only after the patch transaction succeeds, so failed
  attachment cannot leave an active-range owner behind.
- If registration succeeds but a later pre-patch step fails, state destruction
  first calls `RtlDeleteFunctionTable`; it frees the allocation only after
  successful deregistration. If Windows refuses deregistration, the process
  fails fast instead of freeing memory still visible to the unwinder.
- Patch-write failures use the rollback transaction. Recoverable failures
  return only after original bytes and page protection are restored;
  unprovable rollback is fail-fast. Detach/unregister failure is covered by
  the deterministic retry test.

This is a static ownership/control-flow proof, not injected Windows API
failure testing. Deterministic injection remains a possible future enhancement;
the exact-head Windows acceptance run is still required.

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

- Exact PR head validated: `f4cc4d1715cef026585cf14650659981f891ace4`.
- Current-head CI run [#44561390158](https://github.com/Jue-dev/Tessera/actions/runs/44561390158) succeeded: x86/x64 Debug/Release matrix, CTest, SDK staging, Detours x86/x64, no-RTTI quality gate, MSVC /analyze, and package checks. Release publication skipped as expected.
- The current-head run validates the expanded unwind tests, source-metadata bounds checks, ENDBR boundary rejection, bounded unwind-slot serialization, unregister retry, patch rollback tests, and DLL unload-order fixture at aggregate CTest level.
- Artifacts were uploaded for all four SDK configurations.
- The separate five-minute Clang libFuzzer + ASan/UBSan campaign has **not** been run on this exact head. The earlier campaign is not current-head evidence.
- A green CI run is not proof of real host integration: the fixture verifies a controlled admission/drain sequence, but the application must gate every target entry and raw/escaped trampoline use.

## Current status

The Windows CI matrix and full quality gates are green on the exact PR head. Remaining work is a source-level independent failure-path audit, real host admission/drain/unload acceptance, and current-head sustained sanitizer campaign if Actions quota permits. The separate checklist is refreshed to reflect evidence and remaining gates.

The PR remains draft and Issue #6 remains open. No merge or release has been performed.

## Definition of done

Do not close Issue #6 until the current-head Windows matrix and required fuzz validation have evidence, full quality gates are reviewed, host-side admission/module-unload integration is validated, and the final failure-path audit is complete or remaining limitations are explicitly accepted.
