# Native hook stability plan

## Goal and non-goals

The goal is a predictable in-process x86/x64 inline hook backend for explicitly
supported Windows configurations. Unsupported instruction layouts, unsupported
unwind layouts, invalid thread states, conflicting patches, and unavailable
process mitigations must fail closed before target bytes are changed.

No inline-hook implementation can promise to work for every function, every
compiler output, every process mitigation, or arbitrary concurrent thread
creation without cooperation from the host application. The release contract
must describe a tested support envelope rather than claim universal operation.

## Current verified baseline

- Tessera owns a bounded x86/x64 instruction decoder and rejects truncated or
  unsupported encodings instead of guessing instruction boundaries.
- The native backend relocates the currently supported relative branches and
  x64 RIP-relative memory references, and uses a near relay when a 64-bit
  detour is outside rel32 reach.
- Entry writes use a rollback-capable patch transaction. Failure to restore
  executable bytes, cache state, or page protection is fail-fast rather than a
  silent return with uncertain code.
- CET IBT landing pads are recognized and preserved; generated trampoline
  entry points begin with an architecture-matched ENDBR instruction.
- Strict thread policy snapshots, suspends and inspects enumerated threads.
  Best-effort and no-suspension modes are explicitly weaker and require host
  quiescence. Snapshot-based suspension is not a thread-creation barrier.
- Hook tokens retain backend state until detach succeeds. Calls through
  `Hook::operator()` hold an internal shared lease, and lifecycle operations
  wait for those leased calls to complete. Per-thread nesting avoids
  re-locking the non-recursive shared mutex during recursive calls through the
  same Hook object. The public `original()` pointer is still non-owning and
  bypasses the lease; raw-pointer users must stop new calls and drain all users
  before detach, destruction, or module unload.
- The installed-state query is atomic, so observing `installed()` does not
  recursively acquire the callable lease lock.
- Exact-head sustained campaigns on commit `f3b40519` passed independently:
  x86 MSVC Fuzzer + ASan ran 301 seconds / 5,117,733 inputs / 1,151 features
  (523 MB peak RSS); x64 LLVM libFuzzer + ASan/UBSan ran 301 seconds /
  4,790,089 inputs / 942 coverage counters / 1,956 features (531 MB peak RSS).
  No crash or sanitizer report was produced.
- Full CTest on that exact commit remains **failing**: x86 remote process region
  enumeration, a resolver invalid-length test, and the branching-virtual-base
  RTTI fixture fail. The next revision adds diagnostics and fixes the
  architecture-portable test assumption.
- Address-range membership and overlap now use overflow-safe subtraction and
  have boundary tests at `UINTPTR_MAX`.
- Thread snapshot iteration clears the Win32 last-error value before
  `Thread32Next`, so an unrelated stale error cannot be mistaken for a
  snapshot-enumeration failure.

## Required work before a production-stability claim

### P0 — Unwind and exception correctness on x64

1. Add dynamic function-table metadata for generated trampoline ranges using
   `RtlAddFunctionTable` and unregister it with `RtlDeleteFunctionTable`
   before releasing executable storage.
2. Translate source unwind operations to relocated trampoline offsets. Preserve
   stack allocation, nonvolatile register saves, frame-register setup, and
   their exact instruction-end offsets.
3. Reject chained unwind records, language-handler records, unsupported unwind
   versions/opcodes, or any metadata shape that cannot be translated exactly.
   Do not copy handler-specific data as if it were position independent.
4. Ensure table lifetime is coupled to trampoline lifetime on every success,
   attach failure, detach retry, and destructor path.
5. Add tests that call `RtlLookupFunctionEntry` on a live trampoline, exercise
   stack walking while executing relocated prologues, and verify that table
   lookup stops after successful detach.
6. Test exception propagation and stack walking through each supported
   prologue shape on x64. Where exact translation is unavailable, reject the
   target before patching.

**Exit criterion:** every accepted x64 trampoline has valid runtime unwind
metadata for the instructions it contains; unsupported metadata is rejected
without changing target bytes. A green compile alone is not sufficient.

### P0 — Call admission, trampoline ownership, and teardown

1. Keep the raw function-pointer API explicitly non-owning and unsafe across
   concurrent detach. Do not claim that a detour-only counter closes the race:
   a thread can branch to the detour before it increments that counter, and
   callers can retain `original()` independently.
2. Extend the current lock-backed lease model if new call APIs are added.
   `Hook::operator()` now pins the current callable for the duration of the
   invocation, and install/remove/release wait for those calls. Keep regression
   tests for this behavior. Raw pointers returned by `original()` cannot be
   tracked and continue to require host-side admission and drain.
3. Keep host admission control as a required contract for direct target calls
   and detour callback lifetime. The host must stop new entries and drain
   callbacks before removing or unloading the detour module.
4. Define behavior for detach timeout, shutdown, move assignment, destruction,
   `release()`, and repeated remove. A failed detach must retain all resources
   reachable from the still-installed patch.
5. Add deterministic tests for recursive call leases, call leases racing
   with remove, detach failure and retry, move/destructor behavior, and
   module-lifetime boundaries.

**Exit criterion:** calls made through `Hook::operator()` cannot execute
freed trampoline memory; raw-pointer callers remain clearly documented as
requiring external quiescence.

### P0 — Thread coordination and patch atomicity

1. Keep the strict snapshot policy fail-closed for enumeration, suspension,
   context-query, and resume failures.
2. State plainly that a Toolhelp snapshot does not stop new thread creation.
   Applications must use an admission barrier or install before worker threads
   start when full quiescence is required.
3. Test threads at the first byte, middle, and final byte of the patch range;
   test threads in the trampoline, in a detour callback, and returning from a
   trampoline call.
4. Test simultaneous attach/detach from multiple hook objects and from
   multiple independently linked Tessera copies. The process-wide mutex
   serializes transactions, but the current active-range registry is local to
   each loaded copy; until a shared registry exists, applications must use a
   single Tessera hook-backend image per process.
5. Keep page-boundary, instruction-cache flush, page-protection restore, and
   rollback-failure tests in the release gate.

**Exit criterion:** the documented host-quiescence contract is enforced in
integration tests; overlapping hooks are detected within the supported
single-backend-image configuration.

### P1 — Decoder and relocation validation

1. Keep the decoder bounded and reject unknown encodings. Do not broaden opcode
   coverage without independent decoder tests and relocation tests.
2. Run coverage-guided fuzzing against the production decoder and relocator,
   not only against a small standalone smoke executable.
3. Maintain seed corpora for legacy prefixes, ModRM/SIB addressing, VEX, EVEX,
   relative branches, RIP-relative operands, terminal instructions, truncated
   input, and internal branch targets.
4. Run separate x86 and x64 campaigns with AddressSanitizer and UndefinedBehaviorSanitizer
   where the compiler/runtime combination supports them.
5. Preserve every crash, timeout, or invariant failure as a regression corpus
   input. A weekly Windows x64 Clang libFuzzer + ASan/UBSan workflow and binary
   seed corpus are now checked in; its first completed run and review of any
   findings are still required. Separate x86 campaigns and longer campaigns
   remain outstanding.
6. Differential-check instruction lengths against an independent trusted
   decoder during tests; keep the independent implementation out of the
   production runtime if the project intends to own its decoder.

**Exit criterion:** no unresolved fuzz finding; each accepted input has
consistent metadata and each rejected attach leaves original bytes unchanged.

### P1 — Windows mitigations and environment matrix

1. Test CFG-enabled processes, CET/IBT enabled and disabled, and dynamic-code
   restrictions such as ACG. Detect unavailable executable allocation or
   registration capabilities and return a clear error before patching.
2. Verify behavior with ASLR, DEP/NX, page protections crossing region
   boundaries, and modules loaded at high address-space locations.
3. Run x86 and x64 Debug/Release on the supported Windows versions and hardware
   architectures. Record OS build, compiler version, architecture, and
   mitigation state with each result.
4. Add real application integration tests in addition to synthetic byte-buffer
   tests. Include compiler-generated prologues from MSVC and Clang.
5. Keep Detours integration as an independent backend comparison, not as proof
   that the native backend is safe.

**Exit criterion:** the project publishes an explicit tested OS/compiler/CPU/
mitigation matrix and cleanly rejects unsupported configurations.

### P1 — Lifecycle and operational quality

1. Test repeated attach/detach, multiple simultaneous hooks, attach rollback,
   detach retry, process shutdown, and target code modified by a third party.
2. Add diagnostic events that identify why a hook was rejected without
   exposing unsafe partial state.
3. Add stress runs with long-running worker threads and randomized attach/
   detach scheduling under an application-owned admission gate.
4. Keep benchmarks separate from correctness gates. Performance optimizations
   must not weaken validation, rollback, or lifetime rules.

**Exit criterion:** all supported lifecycle states have repeatable tests and
documented error behavior.

## Release gate

A production-stability release must not be declared until all P0 items are
implemented and tested, all P1 campaigns have completed with no unresolved
findings, and the full Windows CI matrix is green on the exact release commit.
A PR smoke pass is necessary but not sufficient.

Until then, use the backend only where the application can provide call
admission/quiescence, the target prologue is accepted by the decoder, and the
application can keep the detour and callback state alive through a successful
detach.
