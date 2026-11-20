# ADR 0002: Native Inline-Hook Safety and Lifecycle Contract

- **Status**: Accepted
- **Date**: 2026-11-20
- **Related work**: [Issue #24](https://github.com/Jue-dev/Tessera/issues/24); `docs/native-inline-hooks.md`; historical records in `docs/archive/native-hook/`

## Context

Tessera supports a native inline-hook backend on Windows x86/x64. Correctness
requires more than writing a branch at a function entry: instruction boundaries
must be decoded conservatively, displaced instructions must be relocatable,
x64 trampoline unwind behavior must remain valid, and detach must not release
code or metadata while calls are still using them.

Thread enumeration and suspension are not a universal quiescence barrier.
In particular, a snapshot cannot prevent a new thread from starting, and
callers that retain a raw trampoline/original pointer can bypass Tessera's
call-lifecycle tracking.

## Decisions

1. **Fail closed on unsupported instruction forms.** The bounded decoder and
   relocator must reject truncated, reserved, unsupported, or ambiguous forms
   rather than guess instruction lengths or relocation semantics. The decoder
   is not advertised as a complete x86/x64 ISA decoder.
2. **Publish only after preparation succeeds.** Trampoline construction,
   relocation, required x64 runtime-function/unwind metadata registration,
   and patch preparation must complete before the target entry is published.
   Entry writes use rollback-capable transactions and instruction-cache flushes.
3. **Preserve unwind semantics on x64.** Supported unwind operations are mapped
   only at relocated instruction boundaries. Unsupported or malformed unwind
   records and unsupported prologues are rejected. Targets without runtime
   function metadata are accepted only for the explicitly audited,
   stack-neutral leaf subset.
4. **Make callable lifetime explicit.** Calls made through the Hook callable
   interface retain a lease; detach/removal waits for leased calls to drain.
   The lease is thread-affine and non-copyable/non-movable.
5. **Treat `original()` as non-owning.** A raw original/trampoline pointer
   does not acquire a lease. Hosts using it must stop admitting new calls and
   drain all outstanding users before detach, Hook destruction, or unloading
   the module that contains the detour.
6. **Do not overstate thread-suspension guarantees.** Strict, best-effort, and
   no-suspension policies have different guarantees. Toolhelp enumeration is a
   finite snapshot: threads created after snapshot capture are not included and
   may execute during the patch transaction. None of the policies prevents
   concurrent thread creation. Hosts must stop admission of callers that can
   enter the target and drain existing callers where entry can bypass Tessera's
   lease mechanism; a snapshot is not an admission barrier.
7. **Retain retryable ownership on failed teardown.** If detach, rollback, or
   unwind-table unregistration cannot complete safely, the operation must not
   report success or discard the state needed for a retry.
8. **Limit native-hook deployment to one backend image per process.** The
   process-wide hook mutex serializes transactions but the active-hook registry
   is module-local. Independent Tessera backend copies in separate loaded
   modules do not share registry state and can therefore fail to detect
   overlapping ownership. Until a shared process registry exists, only one
   loaded native-hook backend image per process is supported; this boundary is
   documented, not claimed to be runtime-enforced. See
   [Native inline hooks](../native-inline-hooks.md#deployment-boundary-one-backend-image-per-process).
9. **Fail stop when owned thread-handle cleanup fails.** `ScopedThreadList` owns
   each Toolhelp snapshot and opened thread handle. If `CloseHandle` reports
   failure, the backend logs the Win32 error and terminates rather than silently
   dropping ownership from a destructor that cannot return a cleanup status.
   This applies to both snapshot and thread handles and is covered by isolated
   subprocess failure tests.
10. **Retain page-protection restoration ownership.** A failed protection
   restoration during a memory write is represented by a process-bound retry
   ticket in `WriteReport`. The ticket preserves the exact affected range and
   the original protection returned by the successful elevation operation.
   Callers using `write_with_report` must retain the report and retry with
   `MemoryWriter::restore_pending_protections`; a report with outstanding
   tickets is not successful. `Patch` retains such reports across its
   lifecycle. The status-only `write` convenience API can only perform an
   immediate retry and cannot transfer persistent retry ownership to callers.
   See [Memory write protection recovery](../memory-write-recovery.md).

## Consequences

- The supported instruction and unwind envelope is intentionally bounded.
- Fuzzing validates decoding/relocation setup and attach/detach restoration; it
  does not execute arbitrary fuzz-generated instructions or trampolines.
- Passing a fuzz campaign is not equivalent to passing the complete Windows
  test matrix or satisfying production acceptance gates.
- Applications must integrate host-side admission/drain for raw-pointer calls
  and module lifetime. This requirement is part of the API usage contract, not
  an optional performance setting.

## Validation and open obligations

The latest exact-head validation for PR #23 completed successfully on commit
`059660d6b644c87b3d3b8438362abffd0cc83409`:

- [Full CI matrix](https://github.com/Jue-dev/Tessera/actions/runs/44739402959):
  x64/x86 Debug and Release builds, full CTest (13/13 suites per configuration),
  x64/x86 Detours integration, MSVC `/analyze`, and the `/GR-` quality gate all
  passed. The quality gate also ran all six corpus-backed fuzz smoke targets,
  all three benchmark executables, and SDK install/package validation.
- [Native-hook fuzz campaigns](https://github.com/Jue-dev/Tessera/actions/runs/44739402840):
  x86 MSVC Fuzzer + ASan completed 4,097,386 executions in 301 seconds; x64
  LLVM libFuzzer + ASan/UBSan completed 7,084,210 executions in 301 seconds.
  Neither campaign reported a crash or sanitizer finding.
- The x64 unwind metadata extraction in `native_unwind.cpp` was included in
  this exact-head build and analysis matrix.

These results establish the PR's current build/test/fuzz acceptance, not a
universal production-safety certification. Remaining production obligations
are tracked separately in [Issue #24](https://github.com/Jue-dev/Tessera/issues/24):
deterministic Win32 failure injection, cross-image registry coordination,
thread-creation race boundaries, and additional semantic decoder/relocator
validation. Page-protection restoration recovery is implemented in PR #25 and
its exact-head CI passed; independent review and any further API compatibility
review remain tracked in Issue #24.

The archived Issue #6 documents are retained under `docs/archive/native-hook/`
for historical context only; their old CI snapshots are superseded by the
exact-head evidence above. This ADR records the safety contract and does not
claim that the remaining Issue #24 obligations have passed.
