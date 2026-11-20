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

The latest exact-head validation for PR #23 completed successfully on commit
`fb2fdc84dd409b3e8d52c9b04afd1008acf5d041`:

- [Full CI matrix](https://github.com/Jue-dev/Tessera/actions/runs/44736486572):
  x64/x86 Debug and Release builds, full CTest (13/13 suites per configuration),
  x64/x86 Detours integration, MSVC `/analyze`, and the `/GR-` quality gate all
  passed. The quality gate also ran all six corpus-backed fuzz smoke targets,
  all three benchmark executables, and SDK install/package validation.
- [Native-hook fuzz campaigns](https://github.com/Jue-dev/Tessera/actions/runs/44736487041):
  x86 MSVC Fuzzer + ASan completed 3,916,127 executions in 301 seconds; x64
  LLVM libFuzzer + ASan/UBSan completed 7,059,226 executions in 301 seconds.
  Neither campaign reported a crash or sanitizer finding.
- The x64 unwind metadata extraction in `native_unwind.cpp` was included in
  this exact-head build and analysis matrix.

These results establish the PR's current build/test/fuzz acceptance, not a
universal production-safety certification. Remaining production obligations
are tracked separately in [Issue #24](https://github.com/Jue-dev/Tessera/issues/24):
deterministic Win32 failure injection, page-protection restoration recovery,
cross-image registry coordination, thread-creation race boundaries, and
additional semantic decoder/relocator validation.

The archived Issue #6 documents are retained under `docs/archive/native-hook/`
for historical context only; their old CI snapshots are superseded by the
exact-head evidence above. This ADR records the safety contract and does not
claim that the remaining Issue #24 obligations have passed.
