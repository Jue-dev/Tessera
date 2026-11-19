# Issue #6 — Windows x86/x64 validation and acceptance checklist

**Source-code commit tested:** `1cad6ef8095020219a89a7d5bf255228f21f7b77`  
**Full Windows CI:** [run #57 / 44601445116](https://github.com/Jue-dev/Tessera/actions/runs/44601445116)  
**Native-hook stress/fuzz:** [run #52 / 44601445007](https://github.com/Jue-dev/Tessera/actions/runs/44601445007)  
**Snapshot:** 2026-11-19  
**PR #7:** open, draft, not merged. **Issue #6:** open.

This checklist distinguishes verified build/runtime evidence from the remaining production-host and fault-injection obligations. The CI/fuzz results below apply to the exact PR source commit shown above; later documentation-only commits do not change the tested C++ or workflow files.

## 1. Exact-head Windows matrix

- [x] x86 Debug configure/build/CTest and SDK staging.
- [x] x86 Release configure/build/CTest and SDK staging.
- [x] x64 Debug configure/build/CTest and SDK staging.
- [x] x64 Release configure/build/CTest and SDK staging.
- [x] Microsoft Detours integration built and executed on x86.
- [x] Microsoft Detours integration built and executed on x64.
- [x] `/GR-` no-RTTI build, complete CTest, fuzz/benchmark smoke, and SDK install gate.
- [x] MSVC `/analyze` x64 build and CTest.
- [x] All eight active CI jobs passed; tag-only release/package publication was correctly skipped for a pull request.

Run #57 completed successfully. Each architecture/configuration CTest run reported **10/10 tests passed**. In particular, `tessera_test_patch_hook` passed in all four configurations.

Evidence: [CI run #57 / 44601445116](https://github.com/Jue-dev/Tessera/actions/runs/44601445116).

## 2. Native x86 runtime verification

- [x] x86 test source is included only in 32-bit builds through `CMAKE_SIZEOF_VOID_P EQUAL 4`.
- [x] The x86 test verifies `stdcall` stack cleanup, detour entry, original trampoline invocation, detach, and restored original target.
- [x] The x86 test verifies `fastcall` register argument forwarding and stack balance through target, detour, and trampoline.
- [x] The x86 test verifies `thiscall` ECX object argument and stack argument behavior through target, detour, and trampoline.
- [x] The x86 test verifies unsupported `rel16 JMP`, `rel16 Jcc`, and `XBEGIN rel16` are rejected without modifying target bytes.
- [x] The complete x86 Debug and Release CTest suites passed on the tested commit.
- [x] Dedicated randomized attach/detach harness processed 65,546 inputs; 60,497 successful hook lifecycles; 2,805 ms; 23,367 inputs/second. The workflow verified a minimum of 52,437 successful lifecycles (80%).
- [x] x86 stress executable PE machine verified as I386 (`0x014c`).

The standalone x86 randomized harness intentionally does **not** execute arbitrary generated instruction bytes or the generated trampoline. Its purpose is safe decoder/relocator and attach/detach lifecycle stress. Actual x86 target/detour/trampoline execution is covered independently by the x86 Catch2 tests listed above. The x86 job is deterministic/randomized stress, **not coverage-guided libFuzzer**.

Evidence: [native-hook run #52 / 44601445007](https://github.com/Jue-dev/Tessera/actions/runs/44601445007), artifact `native-hook-stress-x86-52`.

## 3. Native x64 runtime and unwind verification

- [x] x64 Debug and Release CTest suites passed (10/10 each).
- [x] Native x64 tests execute real target/trampoline calls for relocated instruction and branch cases.
- [x] Unwind tests cover supported v1 unwind operations and multi-slot encodings, frame-register mapping, saved GPR/XMM state, machine-frame records, and relocated prologue offsets.
- [x] Exception/virtual-unwind tests exercise execution inside relocated trampoline prologues.
- [x] Malformed and unsupported metadata is rejected fail-closed, including unsupported version/flags, handlers/chained records, invalid slot streams, unmappable offsets, unreadable ranges, and prologues outside source-function bounds.
- [x] Function-table registration is performed before entry-patch publication.
- [x] Unregister-failure regression verifies the entry patch is reinstalled and ownership/token remain retryable.
- [x] x64 fuzzer executable PE machine verified as AMD64 (`0x8664`).
- [x] Clang libFuzzer + ASan/UBSan campaign completed 301 seconds.
- [x] Campaign executed 7,317,217 units at 24,309 executions/second; 2,754 new corpus units; final libFuzzer metrics: 946 coverage counters, 1,961 features, corpus 805 units / 3,016 bytes; peak RSS 537 MB.
- [x] Campaign exited successfully with no ASan/UBSan report or crash in the campaign log.
- [x] Corpus/crash artifact upload completed.

Evidence: [native-hook run #52 / 44601445007](https://github.com/Jue-dev/Tessera/actions/runs/44601445007), artifact `native-hook-libfuzzer-x64-52`.

This campaign exercises the real native backend with instrumented fuzz inputs, but arbitrary mutated code bytes are not executed as functions. Real trampoline execution and unwind behavior are separately exercised by the x64 runtime regression tests.

## 4. Source-level failure-path review (reviewed, not fully fault-injected)

- [x] Attach keeps unpublished state under `unique_ptr`; registry capacity is reserved before changing target code.
- [x] Trampoline bytes and unwind metadata are finalized before executable protection and unwind registration.
- [x] `RtlAddFunctionTable` success is recorded before the entry patch is published.
- [x] If an attach path fails after registration but before publication, state destruction attempts to unregister; if Windows refuses unregister, the process fails fast rather than freeing memory still referenced by the function table.
- [x] Patch writes use a transaction that records protection, flushes the instruction cache, and attempts byte/protection rollback on failure.
- [x] Unconfirmed rollback or thread-resume failure uses fail-fast rather than returning a false success.
- [x] Detach preserves ownership and a retryable token on recoverable conflict/unregister failure; unregister failure attempts to reinstall the entry patch.
- [x] Thread suspension is RAII-managed and strict policy fails on enumeration/suspend/context failures.
- [ ] Independent reviewer audit of every error edge, including interactions between thread suspension, patch rollback, unwind registration, registry ownership, and token validity.
- [ ] Deterministic Windows API failure injection for allocation, VirtualProtect, FlushInstructionCache, RtlAddFunctionTable, RtlDeleteFunctionTable, thread enumeration/suspend/context, and rollback failures. Existing transaction tests do not inject every Win32 API edge.

## 5. Production host admission, detach, and unload

- [x] The test DLL fixture demonstrates a controlled admission gate, active detour drain, successful detach, DLL unload, and original-target call after unload.
- [x] The public API documents that `Hook::acquire()` is a thread-affine scoped lease.
- [x] The public API documents that raw pointers returned by `original()` are non-owning and not tracked by the lease system.
- [ ] Integrate the admission gate into the real Tessera host/application call paths.
- [ ] Prove all direct target entries, callback entries, saved raw trampoline pointers, and escaped callable references are stopped and drained before detach/unload.
- [ ] Require explicit successful `remove()` before unloading detour code; define safe ownership behavior for remove failure.
- [ ] Define and enforce the host's thread-creation policy. A Toolhelp thread snapshot is not a barrier against new thread creation.

The DLL fixture verifies a controlled protocol; it is not evidence that an external production host already routes every call through that protocol.

## 6. Workflow and dispatch

- [x] Exact-head PR CI automatically ran and completed successfully.
- [x] The branch's native-hook workflow contains a `workflow_dispatch` trigger and the default branch also contains a workflow at the same path with `workflow_dispatch`.
- [x] Native x86/x64 jobs ran automatically for the PR and uploaded both artifacts.
- [ ] If the GitHub UI still reports “Workflow dispatch unavailable”, identify the exact workflow entry/path and selected ref in the UI before changing the default branch. This UI-specific message was not reproduced by the successful PR-triggered run.
- [x] Release publication remains restricted to version-tag pushes.
- [x] No merge, tag, or release was performed.

## 7. Acceptance plan / merge gate

1. **Architecture correctness — PASS:** exact-head x86/x64 Debug and Release CTest, including architecture-specific native hook tests.
2. **Live integration and toolchain — PASS:** Detours x86/x64, no-RTTI gate, static analysis, package/install validation.
3. **Native stress/fuzz — PASS:** x86 65,546-case randomized attach/detach run and x64 301-second ASan/UBSan coverage-guided campaign.
4. **Failure injection — OPEN:** add deterministic injectable wrappers or test seams for allocation, protection, cache flush, function-table registration/unregistration, thread operations, and rollback. Assert bytes, protection, active registry, token, and function-table lifetime after each injected failure.
5. **Production host integration — OPEN:** add host-level admission/drain tests for every direct and indirect call path and prove successful detach before module unload.
6. **Independent audit — OPEN:** review all state transitions and failure paths after injection/host integration.
7. **Final exact-head revalidation — OPEN:** run the full Windows matrix and the focused native campaign again after any code changes in steps 4–6. Do not use stale run evidence for a newer code commit.

## Current conclusion

**x86 and x64 architecture-level build/runtime validation passes on source commit `1cad6ef8095020219a89a7d5bf255228f21f7b77`.** The previous x86 short-runtime concern is resolved by evidence: the 65,546-input harness actually ran, and the x86 ABI/trampoline tests also executed in both Debug and Release CTest.

This is **not** a claim of universal production safety. The remaining blockers for closing Issue #6 or merging PR #7 are deterministic Windows API failure injection, real-host admission/drain/unload integration, and independent review. Keep PR #7 draft/open and Issue #6 open until those gates are completed or explicitly accepted.
