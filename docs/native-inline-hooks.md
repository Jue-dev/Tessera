# Native inline hook backend

Tessera includes an in-process x86/x64 inline hook backend. When
`TESSERA_WITH_DETOURS=OFF`, `default_hook_backend()` selects this backend and
does not require Microsoft Detours. When Detours is enabled, the existing
Detours backend remains the default; applications can still explicitly pass
`&native_inline_hook_backend()` to `Hook::create`.

## Example

```cpp
using Fn = int(__cdecl*)(int);

Fn original_function = nullptr;

int __cdecl my_detour(int value) {
    // Keep this callback non-throwing and safe for concurrent calls.
    return original_function(value) + 1;
}

auto hook = tessera::Hook<Fn>::create(
    &target_function, &my_detour,
    &tessera::native_inline_hook_backend());

if (!hook) {
    // Inspect hook.error().
    return;
}

// Application-level admission gate: prevent new target_function() calls and
// drain all existing calls before installing. Keep the gate closed until the
// detour's trampoline pointer and all callback state have been published.
tessera::HookOptions options{};
options.threads = tessera::ThreadPolicy::SuspendOthersStrict;

auto installed = hook->install(options);
if (!installed) {
    // Unsupported prologues and unsafe thread states fail closed.
    return;
}

original_function = hook->original();
// Re-open the application-level gate only after original_function is ready.

// Close the gate again and drain every in-flight detour/original call before
// removing the hook. Do not remove from inside my_detour().
auto removed = hook->remove();
original_function = nullptr;
```

## Safety and compatibility contract

- The native backend patches executable code in the **current process only**.
  It is not a remote-process injector. The shared `HookCore` validates that
  both target and detour addresses are executable in the current process and
  rejects identical target/detour addresses before reaching a backend.
- Both x86 and x64 use a 5-byte relative entry jump. On x64, the backend
  first attempts a direct `E9 rel32` to the detour; when it is out of range,
  it jumps to a relay stored after the trampoline in the same near allocation.
  The relay performs a 14-byte absolute indirect jump to the detour. The
  trampoline allocation is kept within rel32 reach of the target so RIP-relative
  operands and the relay remain addressable.
- The trampoline copies whole instructions, relocates supported relative
  control-flow operands and x64 RIP-relative memory operands, and jumps back
  to the first untouched byte with a 5-byte `E9 rel32` return transfer.
  The position-independent-code idiom `CALL $+5` (which materializes the
  original instruction pointer on the stack) is rejected because a relocated
  CALL would expose the trampoline address instead.
- The native backend does not synthesize or register Windows x64
  `RUNTIME_FUNCTION` / unwind metadata for generated trampoline code. Normal
  execution leaves the trampoline after the relocated prologue and continues
  in the original function, where the original image unwind metadata applies.
  Exception unwinding or asynchronous stack walking while the instruction
  pointer is still inside the generated trampoline prologue is not guaranteed.
  Targets whose stolen prologues may fault or require reliable unwinding during
  that brief window should use a backend that provides suitable unwind support.
- The native backend uses Tessera's private, bounded x86/x64 instruction
  decoder in `src/hook/backends/x86_instruction_decoder.hpp`. It is scoped to
  instruction-boundary and relocation metadata needed by native hooks; it is
  not a public general-purpose disassembler. The decoder handles the legacy,
  VEX, and EVEX forms exercised by the native-hook validation suite, enforces
  the architectural 15-byte instruction limit, and rejects truncated or
  unsupported encodings before target bytes are changed. Tessera owns the
  decoder, backend, trampoline allocation, relocation, patch transaction,
  thread coordination, rollback, and lifecycle management.
- Unsupported or out-of-range relocations are rejected before the target is
  modified. The backend deliberately does not guess instruction lengths or
  silently truncate branches. A prologue that reaches a terminal `RET`,
  `JMP`, `IRET`, or indirect jump before the five-byte entry patch is complete
  may use only recognized NOP/INT3 padding for the remaining bytes. Resumable
  trap instructions such as `INT3` and `UD2` are decoded as instructions,
  not assumed to terminate control flow. Embedded data or unrelated instructions
  after an actual terminal transfer are rejected instead of being decoded and
  overwritten as code.
- Short unconditional `JMP rel8` branches are expanded to `E9 rel32`, and
  all sixteen short conditional `Jcc rel8` opcodes are expanded to their
  equivalent `0F 8x rel32` form. Unprefixed short `JMP`/`Jcc` forms are
  normalized; prefixed variants are rejected rather than silently dropping a
  prefix. `LOOP`, `LOOPE`, `LOOPNE`, and `JCXZ`-family short branches keep
  their original instruction and prefixes and use two nearby `E9 rel32`
  dispatch jumps. This preserves the counter-register and flags semantics
  without synthesizing a different conditional instruction. Branches into
  instruction boundaries inside the stolen prologue are remapped to relocated
  instruction offsets; branches into the middle of an instruction are rejected
  without patching.
- Attach and detach patch writes keep the target writable until the new
  instruction bytes have been flushed. If that flush fails, or restoring the
  prior page protection fails, the backend copies the prior bytes back while
  the page is still writable, retries the rollback cache flush once, and
  retries protection restoration once. If either rollback step still fails,
  the backend calls `std::terminate()`: returning to application code with
  uncertain executable bytes or page protection would be unsafe. Recoverable
  failures return an error only after the prior bytes and protection have been
  restored. Detach therefore either completes and invalidates its token or
  leaves the installed hook/token valid for a retry.
- CET Indirect Branch Tracking is supported at hook and trampoline entry
  points. Existing target landing pads (`ENDBR64`/`ENDBR32`) are detected
  and preserved; the five-byte entry patch is placed immediately after the
  four-byte landing pad. Every trampoline begins with an architecture-matched
  ENDBR instruction, including when the original target did not have one, so
  indirect calls through `original()` have a valid IBT landing point.
- Existing common `E9 rel32` and `FF 25` entry thunks are rejected rather
  than stacked. An active-range registry also prevents two native hooks from
  owning overlapping instruction bytes. Detach verifies that the target bytes
  still match the bytes installed by this hook, so it will not overwrite a
  later patch.
- The thread that calls `install()` or `remove()` is never suspended or
  inspected by the backend. The caller must ensure that this thread is outside
  the overwritten entry range (and, during detach, outside the trampoline) and
  cannot return into bytes being patched. Application-level admission and drain
  must cover the calling thread as well as every other thread.
- The named process-wide transaction mutex serializes patch transactions
  across static Tessera copies, but the active-range registry is currently
  local to each loaded backend image. Therefore, loading multiple independent
  static copies into one process is not a supported configuration: the mutex
  alone cannot make their overlap registries coherent. Use one Tessera hook
  backend image per process until a shared cross-image registry is implemented.
- If Windows reports that the previous mutex owner terminated while holding
  the mutex (`WAIT_ABANDONED`), the backend calls `std::terminate()`: the
  previous owner may have died during an executable-code write, so registry
  and target-byte consistency cannot be proven safely.
- `SuspendOthersStrict` (the default) takes a Toolhelp thread snapshot,
  suspends the enumerated process threads during the short patch transaction,
  checks their instruction pointers, and fails if an enumerated thread cannot
  be suspended/inspected or is in the overwritten range. Threads created after
  that snapshot are not included, so strict suspension is not a thread-creation
  barrier or a substitute for application-level call admission.
  `SuspendOthersBestEffort` may skip threads that cannot be suspended; the
  caller must establish quiescence for those threads. `None` performs no
  coordination and is intended only when the caller has already established
  an externally quiescent patch window. The native backend requests only
  suspend, context-read, and synchronization rights. The Microsoft Detours
  backend additionally requests `THREAD_SET_CONTEXT`, because Detours may
  rewrite an enlisted thread's instruction pointer when its transaction commits.
  Suspended threads are resumed in reverse order. If `ResumeThread` fails, the backend uses a zero-time
  `WaitForSingleObject` check to distinguish a terminated thread from a live
  or unqueryable one; the latter cases call `std::terminate()` rather than
  return while potentially leaving a process thread suspended. This avoids
  treating the valid thread exit code `STILL_ACTIVE` as proof that a thread
  is still running.
- Thread suspension protects the patch transaction; it is **not** an
  application call-admission mechanism or an in-flight call reclamation
  mechanism. Installation must also be externally gated: keep new target calls
  blocked until the trampoline pointer and all detour callback state are
  initialized and published. Otherwise a resumed thread can enter the detour
  before the application has stored the trampoline pointer. Thread suspension
  also cannot determine whether application code is inside a detour callback
  that may call the trampoline later.
  `original()` returns a raw function pointer and does not acquire a lifetime
  lease. The application must stop new calls, wait for every in-flight detour
  callback and original/trampoline call to finish, and only then call
  `remove()`, destroy the hook, or unload the module containing the detour.
  Do not remove a hook from inside its own detour callback. Tessera does not
  currently provide an owning call lease for raw trampoline pointers.
- Concurrent calls to `install()`, `remove()`, move operations, or destruction
  on the same `Hook` object require external synchronization. The backend's
  process-wide lock serializes patch transactions across hook objects; it does
  not make the public `Hook` wrapper or a detour's application state thread-safe.
- Tessera does not expose an automatic in-flight counter or call lease for
  this API. A counter entered from the detour body alone cannot close the race
  between a thread branching to the detour and incrementing that counter;
  additionally, callers can retain and invoke the raw pointer returned by
  `original()` without passing through the `Hook` object. A correct reclamation
  protocol therefore needs application-level admission control around both
  target calls and every retained trampoline call, followed by a drain before
  detach. Do not treat a detour-only reference count as sufficient.
- Hooks should be installed early where practical. Functions with unsupported
  short-branch layouts or prologues too close to a page boundary fail with an
  error instead of being patched.
- The `Hook` destructor makes a best-effort detach attempt, but it cannot
  return a cleanup error. Call `remove()` explicitly and check its result
  before destruction when a detach failure is possible. If that attempt fails,
  the target may remain patched and the backend deliberately retains resources
  rather than freeing a trampoline that could still be executing. Keep the
  detour module and all callback state alive until the patch is known to be
  removed or the process exits.
- `release()` intentionally leaves a hook installed and transfers cleanup
  responsibility to the application for process lifetime. It does not return
  an owning RAII handle; do not unload the detour module or free any state it
  uses while the released hook can still route calls into it.

## Validation

The `[hook][native]` tests cover real in-process attach/trampoline/detach,
x64 RIP-relative memory operands, execution of all sixteen short `Jcc`
conditions with deterministic flags and both taken/fall-through results,
`CALL $+5` rejection without patching,
short `JMP`, `LOOP`/`LOOPE`/`LOOPNE`/`JCXZ` taken and fall-through paths,
address-size-prefixed counter branches, rel32 `CALL`/`JMP`/near-`Jcc`
relocation, VEX/EVEX decode-and-copy (without executing AVX instructions),
internal branch remapping, branch-into-instruction rejection, RIP-relative
references into overwritten bytes, safe terminal-prologue padding versus
embedded-data rejection, common thunk rejection, non-executable target and detour rejection,
external tail-jump target
preservation, CET IBT landing-pad preservation and trampoline entry validation,
x64 direct-entry and near-relay destinations, ENDBR-prefixed trampoline entry points, five-byte
trampoline return jumps, multiple simultaneous hooks,
page-protection restoration, page-boundary rejection, overlapping patch
rejection, detach conflict preservation and retry, and a fixed-seed 256-sample
malformed-prologue stress corpus that verifies rejected bytes remain unchanged
and accepted hooks can be removed cleanly. The overflow-safe address-range
helper is unit-tested at `UINTPTR_MAX`, including wrapped-end, zero-length,
and half-open boundary cases. A real worker-thread integration test
exercises strict suspend/context/resume coordination. A separate four-worker
integration test performs repeated attach/detach cycles under an application-owned
shared/exclusive admission gate, ensuring callbacks and trampoline calls drain
before executable bytes or trampoline storage are changed. Mock-backend tests
cover exception containment and retryable detach failures. Patch-transaction tests exercise deterministic Win32-operation
failures, rollback ordering, page-protection restoration, and preservation of
the first native error.

The Windows native-hook fuzz smoke target also runs nine focused decoder/relocator seeds plus 512 deterministic random prologues (`0xC0FFEE42`) on every full quality-gate run. Each accepted sample must detach and restore its original bytes; each rejected sample must leave the target bytes unchanged. This is a reproducible smoke corpus, not a replacement for long-running coverage-guided fuzzing with LLVM libFuzzer.

The Windows validation workflows run at multiple stages:
`.github/workflows/pr-smoke.yml` validates qualifying pull requests with x86
and x64 Debug and Release build/test jobs. `.github/workflows/ci.yml` performs
the full x86/x64 Debug and Release matrix, the `/GR-` quality gate (including
fuzz/benchmark smoke targets), Detours integration, and MSVC static analysis.
The full workflow runs for qualifying source/build pushes to `main`, version
tags, manual dispatch, and its weekly schedule. A successful Debug smoke job
does not replace the Release, Detours, or static-analysis checks.
