# Issue #6 — Windows x86/x64 validation and acceptance checklist

**Tested source commit:** `6586750f2faa8683ad90e7fc87e697c30dd19be1` (code unchanged from the previously validated source; this commit updates documentation only)  
**Full Windows CI:** [run #58 / 44603747013](https://github.com/Jue-dev/Tessera/actions/runs/44603747013)  
**Native-hook stress/fuzz:** [run #54 / 44603747347](https://github.com/Jue-dev/Tessera/actions/runs/44603747347)  
**Snapshot:** 2026-11-19  
**PR #7:** open, draft, not merged. **Issue #6:** open.

This checklist distinguishes verified build/runtime evidence from the remaining production-host and fault-injection obligations. All code tests below were executed on the exact source commit `1cad6ef8095020219a89a7d5bf255228f21f7b77`; the later `6586750f2faa8683ad90e7fc87e697c30dd19be1` commit only updates documentation, and the exact documentation head was revalidated by CI.

## 1. Exact-head Windows matrix

- [x] x86 Debug configure/build/CTest and SDK staging.
- [x] x86 Release configure/build/CTest and SDK staging.
- [x] x64 Debug configure/build/CTest and SDK staging.
- [x] x64 Release configure/build/CTest and SDK staging.
- [x] Microsoft Detours integration built and executed on x86.
- [x] Microsoft Detours integration built and executed on x64.
- [x] `/GR-` no-RTTI build, complete CTest, fuzz/benchmark smoke, and SDK staging/install gate.
- [x] MSVC `/analyze` x64 build and CTest.
- [x] All eight active CI jobs passed; tag-only release/package publication was correctly skipped for a pull request.

Run #58 completed successfully. Each architecture/configuration CTest run reported **10/10 tests passed**. The native `tessera_test_patch_hook` test passed in all four configurations. Detours x86/x64, no-RTTI, static analysis, and packaging/install checks passed.

Evidence: [CI run #58 / 44603747013](https://github.com/Jue-dev/Tessera/actions/runs/44603747013).

## 2. Native x86 runtime verification

- [x] x86 test source is included only in 32-bit builds through `CMAKE_SIZEOF_VOID_P EQUAL 4`.
- [x] x86 tests verify `stdcall` stack cleanup, detour entry, original trampoline invocation, detach, and target restoration.
- [x] x86 tests verify `fastcall` register argument forwarding and stack balance through target, detour, and trampoline.
- [x] x86 tests verify `thiscall` ECX object argument and stack argument behavior through target, detour, and trampoline.
- [x] x86 tests verify unsupported `rel16 JMP`, `rel16 Jcc`, and `XBEGIN rel16` are rejected without modifying target bytes.
- [x] Complete x86 Debug and Release CTest suites passed.
- [x] Dedicated randomized attach/detach harness processed **65,546 inputs; 60,497 successful hook lifecycles; 3,783 ms; 17,326 inputs/second**.
- [x] The workflow enforces at least 52,437 successful lifecycles (80% of 65,546), nonzero elapsed time, and nonzero throughput.
- [x] Stress executable PE machine verified as I386 (`0x014c`).

The standalone x86 harness does **not** execute arbitrary generated instruction bytes or the generated trampoline. Its purpose is decoder/relocator and attach/detach lifecycle stress. Actual x86 target/detour/trampoline execution is covered independently by x86 Catch2 ABI tests. The x86 job is randomized deterministic stress, **not coverage-guided libFuzzer**.

Evidence: [native-hook run #54 / 44603747347](https://github.com/Jue-dev/Tessera/actions/runs/44603747347), artifact `native-hook-stress-x86-54`.

## 3. Native x64 runtime and unwind verification

- [x] x64 Debug and Release CTest suites passed (10/10 each).
- [x] Native x64 tests execute real target/trampoline calls for relocated instruction and branch cases.
- [x] Unwind tests cover supported v1 unwind operations and multi-slot encodings, frame-register mapping, saved GPR/XMM state, machine-frame records, and relocated prologue offsets.
- [x] Exception/virtual-unwind tests exercise execution inside relocated trampoline prologues.
- [x] Malformed and unsupported metadata is rejected fail-closed, including unsupported version/flags, handlers/chained records, invalid slot streams, unmappable offsets, unreadable ranges, and prologues outside source-function bounds.
- [x] Function-table registration is performed before entry-patch publication.
- [x] Unregister-failure regression verifies the entry patch is reinstalled and ownership/token remain retryable.
- [x] x64 fuzzer executable PE machine verified as AMD64 (`0x8664`).
- [x] Clang libFuzzer + ASan/UBSan campaign completed **301 seconds**.
- [x] Campaign executed **7,235,656 units** at **24,038 executions/second**; **2,710 new corpus units**; final metrics **942 coverage counters, 1,958 features, 806 corpus units / 3,072 bytes**; peak RSS **535 MB**.
- [x] Campaign exited successfully with no ASan/UBSan report or crash in `campaign.log`.
- [x] Corpus/crash artifact upload completed and artifact was downloaded and inspected.

Evidence: [native-hook run #54 / 44603747347](https://github.com/Jue-dev/Tessera/actions/runs/44603747347), artifact `native-hook-libfuzzer-x64-54`.

The campaign log was inspected directly. It ends with `DONE` and `Done 7235656 runs in 301 second(s)`, with no sanitizer diagnostic or crash reproducer. Arbitrary mutated bytes are not executed as functions; real trampoline execution and unwind behavior are separately exercised by x64 runtime regression tests.

## 4. Source-level failure-path review (reviewed, not fully fault-injected)

- [x] Attach keeps unpublished state under `unique_ptr`; registry capacity is reserved before changing target code.
- [x] Trampoline bytes and unwind metadata are finalized before executable protection and unwind registration.
- [x] `RtlAddFunctionTable` success is recorded before entry-patch publication.
- [x] If attach fails after registration but before publication, state destruction attempts unregister; refusal fails fast rather than freeing memory still referenced by the OS function table.
- [x] Patch writes use a transaction that records protection, flushes instruction cache, and attempts byte/protection rollback on failure.
- [x] Unconfirmed rollback or thread-resume failure uses fail-fast rather than returning false success.
- [x] Detach preserves ownership and a retryable token on recoverable conflict/unregister failure; unregister failure attempts to reinstall the entry patch.
- [x] Thread suspension is RAII-managed and strict policy fails on enumeration/suspend/context failures.
- [ ] Independent reviewer audit of every error edge, including interactions between thread suspension, patch rollback, unwind registration, registry ownership, and token validity.
- [ ] Deterministic Windows API failure injection for allocation, VirtualProtect, FlushInstructionCache, RtlAddFunctionTable, RtlDeleteFunctionTable, thread enumeration/suspend/context, and rollback. Existing transaction tests inject patch-write operations, but not every real Win32 API edge.

## 5. Production host admission, detach, and unload

- [x] DLL fixture demonstrates a controlled admission gate, active detour drain, successful detach, DLL unload, and original-target call after unload.
- [x] Public API documents that `Hook::acquire()` is a thread-affine scoped lease.
- [x] Public API documents that raw pointers returned by `original()` are non-owning and not tracked by the lease system.
- [ ] Integrate the admission gate into the real Tessera host/application call paths.
- [ ] Prove all direct target entries, callback entries, saved raw trampoline pointers, and escaped callable references are stopped and drained before detach/unload.
- [ ] Require explicit successful `remove()` before unloading detour code; define safe ownership behavior for remove failure.
- [ ] Define and enforce host thread-creation policy. Toolhelp snapshot is not a barrier against new thread creation.

The DLL fixture verifies a controlled protocol; it does not prove an external production host routes every call through that protocol.

## 6. Workflow and dispatch

- [x] Exact-head PR CI automatically ran and completed successfully.
- [x] Native-hook workflow has `workflow_dispatch` on the PR branch and default branch.
- [x] PR-triggered x86/x64 jobs ran and uploaded artifacts.
- [ ] If the UI still reports “Workflow dispatch unavailable”, capture the exact workflow entry/path and selected ref. This UI-specific message was not reproduced by successful PR-triggered runs.
- [x] Release publication remains restricted to version-tag pushes.
- [x] No merge, tag, or release was performed.

## 7. Acceptance plan / merge gate

1. **Architecture correctness — PASS:** exact-head x86/x64 Debug and Release CTest, including architecture-specific native-hook tests.
2. **Live integration and toolchain — PASS:** Detours x86/x64, no-RTTI gate, static analysis, package/install validation.
3. **Native stress/fuzz — PASS:** x86 65,546-input randomized attach/detach run; x64 301-second ASan/UBSan coverage-guided campaign.
4. **Failure injection — OPEN:** add deterministic injectable wrappers/test seams for allocation, protection, cache flush, function-table registration/unregistration, thread operations, and rollback. Assert target bytes, protection, active registry, token, and function-table lifetime after each failure.
5. **Production host integration — OPEN:** host-level admission/drain tests for every direct and indirect call path and successful detach before module unload.
6. **Independent audit — OPEN:** review all state transitions and failure paths after injection/host integration.
7. **Final exact-head revalidation — OPEN:** full Windows matrix and focused native campaign after any code changes in gates 4–6; do not reuse stale evidence.

## Current conclusion

**x86 and x64 architecture-level build/runtime validation is PASS.** The short x86 runtime concern is resolved: the 65,546-input harness ran and its minimum successful-lifecycle threshold passed; x86 ABI/trampoline tests also executed in Debug and Release.

This is **not** a claim of universal production safety. Remaining blockers for closing Issue #6 or merging PR #7 are deterministic Windows API failure injection, real-host admission/drain/unload integration, and independent review. Keep PR #7 draft/open and Issue #6 open until those gates are completed or explicitly accepted.
