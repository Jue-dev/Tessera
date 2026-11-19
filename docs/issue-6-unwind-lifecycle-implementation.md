# Issue #6 implementation plan: unwind metadata and call admission

This branch tracks the work for issue #6. The changes are staged deliberately:
unsupported unwind shapes and call paths must remain fail-closed until they have
correct implementation and Windows tests.

## Scope and constraints

- x64 runtime-function registration is separate from x86; x86 does not use
  Windows x64 `RUNTIME_FUNCTION` tables.
- The native backend currently emits a trampoline containing an ENDBR landing
  pad, relocated instructions, and a jump back. It does not emit x64 unwind
  metadata for that generated range.
- `Hook::operator()` already takes an internal callable lease. This lease does
  not protect direct calls to the target or raw pointers obtained from
  `original()`.
- Thread snapshots are not an admission barrier. Host code must prevent new
  entries and drain active calls before detach or module unload.

## Milestones

### M0 — Baseline and design (this change)

- Record the current trampoline layout and explicit unsupported cases.
- Define the unwind metadata ownership/lifetime contract.
- Define an opt-in call-lease API contract without pretending it protects
  unleased raw function pointers.
- Keep issue #6 open until code and tests meet its acceptance criteria.

### M1 — Unwind metadata model (x64 only)

- Add a private representation for a generated trampoline's
  `RUNTIME_FUNCTION` and `UNWIND_INFO` storage.
- Keep metadata allocation separate from executable allocation and ensure both
  are owned by the hook state.
- Register with `RtlAddFunctionTable` only after code and metadata are fully
  initialized and before publishing the trampoline.
- Unregister with `RtlDeleteFunctionTable` only after successful detach and
  call quiescence; if unregister fails, retain resources and fail safely.
- Initially support only unwind operations that can be mapped exactly through
  the relocation map. Reject chained records, language handlers, handler data,
  unsupported unwind versions/opcodes, and ambiguous mappings before target
  bytes are modified.
- Do not synthesize unwind codes for instructions unless the backend can prove
  the prologue operation and its relocated end offset.

### M2 — Call admission and drain

**Partial implementation:** `Hook::acquire()` now returns a non-copyable, non-movable scoped callable lease. Its `get()` exposes the current callable only while the lease is alive; lifecycle operations take the exclusive lock and wait for the lease. A deterministic test exercises explicit lease acquisition and remove/drain ordering. This is not a complete host admission barrier and cannot track pointers that escape the scope.

- Add an explicit RAII lease API for calls routed through Tessera. A lease
  exposes the callable pointer while retaining the lifecycle lock until its
  scope ends.
- Keep `original()` as a clearly documented unsafe/non-owning snapshot for
  compatibility; do not imply that a lease tracks pointers copied earlier.
- Test admission racing with remove, nested leases, move/cleanup constraints,
  detach failure/retry, and callback/module lifetime.
- Host-side entry admission remains required for direct target calls and
  callbacks that can be invoked by code outside the lease API.

### M3 — Windows validation

- Add x64 tests for `RtlLookupFunctionEntry` on live trampolines.
- Add stack-walk/exception tests through each supported relocated prologue.
- Verify registration is removed after detach and metadata stays alive during
  leased calls.
- Run x86/x64 Debug and Release CI; run sustained fuzzing and preserve every
  finding as a corpus regression.
- Exercise failure injection for allocation, registration, detach, and
  unregister paths. Target bytes, protections, token ownership, and metadata
  must remain retryable or fail-fast if consistency cannot be proven.

## Definition of done

Issue #6 may close only when all acceptance criteria in the issue are met,
unsupported unwind layouts are rejected before patching, lifetime tests pass,
and the exact Windows CI matrix is green. Documentation-only progress does not
count as completion.
