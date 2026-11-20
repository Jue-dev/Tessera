# ADR 0002: Native Inline-Hook Safety and Lifecycle Contract

- **Status**: Accepted
- **Date**: 2026-11-20
- **Related work**: Issue #6; `docs/native-inline-hooks.md`; `docs/native-hook-stability-plan.md`

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
   no-suspension policies have different guarantees. None independently
   prevents concurrent thread creation; host-side quiescence remains necessary
   where callers can enter outside Tessera's lease mechanism.
7. **Retain retryable ownership on failed teardown.** If detach, rollback, or
   unwind-table unregistration cannot complete safely, the operation must not
   report success or discard the state needed for a retry.

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

The repository's native-hook documentation and Issue #6 audit/checklist remain
the source of exact-head CI evidence and outstanding acceptance gates. In
particular, deterministic Win32 failure injection, protection-restore recovery,
cross-image coordination, and complete current-head Windows CI validation
must not be inferred from this ADR's accepted design decisions.

This ADR records the safety contract; it does not claim that every open
validation obligation has passed.
