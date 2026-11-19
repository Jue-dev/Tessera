# Issue #6 — implementation and validation tracker

This document is the live progress record for native x86/x64 inline-hook unwind
and call-lifecycle safety. The PR remains a draft and Issue #6 remains open
until every required gate below is satisfied.

## Current progress

| Work item | Status | Evidence / remaining work |
|---|---|---|
| x64 dynamic trampoline unwind registration | [x] Implemented | Stable `RUNTIME_FUNCTION` and `UNWIND_INFO` storage; register before publishing the entry patch |
| Version-1 unwind translation | [x] Implemented | Translate supported `CodeOffset` entries through relocated instruction boundaries; preserve extra slots |
| Fail-closed unwind validation | [x] Implemented | Reject unknown/version-2 operations, malformed slot streams, handler/chained records, non-entry targets, and unmappable offsets |
| No-source-record policy | [x] Implemented | Accept only the audited leaf-safe subset; reject stack-changing/non-leaf dynamic code |
| Detach and unregister retry | [x] Implemented | Restore target, drain supported leases, unregister; on unregister failure restore the hook patch and retain retryable ownership |
| Explicit callable lease API | [x] Implemented | `Hook::acquire()`, `get()`, and `target()`; non-copyable, non-movable, thread-affine |
| Deterministic lifecycle/unwind tests | [x] Implemented | Real target-entry → detour → trampoline lease test, SEH in relocated prologue, lookup lifetime, unregister-failure retry, and malformed metadata rejection |
| Windows x86/x64 Debug/Release matrix | [x] Passed | PR Smoke run #96, commit `ad8a378d994522d7bebabde5a70d9330298fac33`; all four jobs and test steps succeeded |
| x64 Release deterministic fuzz smoke | [x] Passed | Included in the x64 Release job of PR Smoke #96 |
| Five-minute Clang libFuzzer + ASan/UBSan campaign | [ ] In progress | Native Hook Coverage-Guided Fuzz run #8; instrumented build succeeded, campaign result/artifact upload not yet confirmed |
| Broader unwind-opcode stack-walk coverage | [ ] Remaining | Current SEH integration test exercises `UWOP_ALLOC_SMALL`; add realistic tests for each accepted opcode family and multi-slot payloads |
| Module unload / host admission ordering | [ ] Remaining review | API cannot intercept raw pointers or prevent unrelated callers from entering; define and test host-side stop-admission → drain → detach → unload ordering |
| Registration/allocation failure injection | [ ] Remaining review | Unregister failure is forced and retry-tested; deterministic failure injection for allocation and `RtlAddFunctionTable` remains outstanding |
| Final independent review and acceptance audit | [ ] Remaining | Re-check patch bytes, page protections, registry ownership, token retryability, and code/data lifetime on every failure edge |

## Implementation contract

### x64 unwind metadata

The trampoline contains an ENDBR landing pad, relocated instructions, a jump
back to the original function, and a separate near relay when needed. On x64,
the backend owns a stable dynamic function-table entry and its unwind bytes in
the trampoline allocation. It registers this metadata after the allocation is
finalized and before publishing the target patch.

When the source address has a Windows runtime-function record, the hook target
must be the function entry. Supported version-1 unwind operations are copied
with their extra slots preserved, and each `CodeOffset` is mapped only when it
lands on an exact relocated instruction boundary. Unsupported versions,
operations, handler/chained records, malformed streams, non-entry targets,
and offsets that cannot be represented are rejected before target bytes are
changed.

When no source runtime-function record exists, only the audited stack-neutral
leaf subset is accepted. The backend does not invent unwind semantics for
stack-changing or non-leaf dynamic code. x86 does not use x64
`RUNTIME_FUNCTION` tables.

Detach restores the target and performs the backend's thread-coordination
check before unregistering the dynamic function table. If unregister fails,
the backend reinstates the entry patch and retains the function table,
allocation, registry ownership, and retryable token. It does not free memory
that Windows may still consult.

### Callable lease and host ownership

`Hook::acquire()` returns a non-copyable, non-movable, thread-affine scoped
lease. `get()` exposes the current original/trampoline callable; `target()`
exposes the target entry so the caller can acquire the lease before entering
the detour. The Hook must outlive the lease, and the lease must be destroyed on
the acquiring thread.

The lease protects calls made while it remains alive, including the detour's
use of a trampoline pointer during that scope. It does **not** track a pointer
that escapes the scope, a direct target call made without first acquiring a
lease, or a call from outside the application-controlled admission protocol.
`original()` remains a raw, non-owning pointer for compatibility.

The host must therefore:
1. Stop admitting new calls to the target and any escaped/raw trampoline path.
2. Wait for every in-flight target call, detour callback, and raw trampoline
   call to finish.
3. Call `remove()` and verify success.
4. Only then destroy hook state or unload the module containing the detour or
   any callback state.

A Toolhelp thread snapshot is not a thread-creation barrier and cannot replace
this host-side admission protocol. Concurrent mutation/destruction of the
same `Hook` object also requires external synchronization.

## Validation record

- PR Smoke #96 passed on x64 Release, x86 Release, x64 Debug, and x86 Debug.
- The x64 Release job also passed the deterministic native-hook fuzz corpus.
- Native Hook Coverage-Guided Fuzz run #8 successfully configured and built
  the Windows x64 clang-cl libFuzzer + ASan/UBSan executable. Its bounded
  campaign and artifact upload have not yet been confirmed.
- Earlier fuzz workflow attempts failed during toolchain/runtime setup. Those
  failures are not counted as successful fuzz campaigns.

## Definition of done

Issue #6 may close only after the sustained fuzz campaign passes, the remaining
unwind-opcode and host module-unload ordering coverage has been reviewed and
tested, the outstanding failure-injection paths are addressed or explicitly
proven unreachable, and a final audit confirms all acceptance criteria from
the issue. This PR is intentionally kept in draft; no merge or release is
performed here.
