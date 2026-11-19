# Issue #6 — native hook implementation and verified status

This record covers Tessera's Windows x86/x64 native inline-hook backend, x64 trampoline unwind metadata, and callable lifetime. The acceptance ledger is [issue-6-ci-validation-checklist.md](issue-6-ci-validation-checklist.md).

## Implemented behavior

- x64 trampoline unwind metadata is generated and registered before publishing the target entry patch.
- Supported v1 unwind operations are validated and mapped only at relocated instruction boundaries. Unsupported handler/chained records, unsupported opcodes/versions, malformed slot streams, unmappable offsets, non-entry targets, and unsupported prologues fail closed.
- Source runtime-function and unwind data are checked for bounds/readability; stolen prologues cannot extend outside the source function.
- Targets with no runtime-function record are accepted only for a small audited stack-neutral leaf-instruction subset.
- Detach/unregister failure restores/reinstalls the entry patch when possible and preserves retryable token/trampoline/table ownership. An unrecoverable rollback does not report success.
- `Hook::acquire()` supplies a non-copyable, non-movable, thread-affine callable lease. `original()` remains a raw non-owning pointer; the API does not claim that it is tracked or safe after host teardown begins.
- x86 ABI tests exercise stdcall, fastcall, and thiscall through target, detour, and trampoline, including stack balance and restoration.
- Regression coverage includes relocation/branch cases, x64 unwind operation/slot variants, malformed metadata, exception unwinding, rollback, unregister retry, and a controlled DLL admission/drain/detach/unload fixture.

## Exact-head validation record

Tested C++ source commit: `1cad6ef8095020219a89a7d5bf255228f21f7b77`. Latest documentation-only PR head: `6586750f2faa8683ad90e7fc87e697c30dd19be1`.

### Full Windows CI

[Run #58 / 44603747013](https://github.com/Jue-dev/Tessera/actions/runs/44603747013) completed successfully on the latest PR head.

- x86 Debug: configure/build, CTest 10/10, SDK stage — pass.
- x86 Release: configure/build, CTest 10/10, SDK stage — pass.
- x64 Debug: configure/build, CTest 10/10, SDK stage — pass.
- x64 Release: configure/build, CTest 10/10, SDK stage — pass.
- Live Microsoft Detours integration: x86 and x64 — pass.
- `/GR-` no-RTTI quality gate, tests, fuzz/benchmark smoke, install — pass.
- MSVC `/analyze` x64 build and CTest — pass.
- Tag-only release publication skipped as expected for a PR.

### Focused native-hook validation

[Run #54 / 44603747347](https://github.com/Jue-dev/Tessera/actions/runs/44603747347) completed successfully on the latest PR head.

**x86:** MSVC x86 toolchain probe and PE I386 check passed. The deterministic harness processed **65,546 inputs; 60,497 successful attach/detach lifecycles; 3,783 ms; 17,326 inputs/second**. It is randomized lifecycle/decoder stress, not coverage-guided libFuzzer, and does not execute arbitrary input bytes. Actual x86 target/detour/trampoline execution is covered by separate x86 CTest ABI cases (stdcall, fastcall, thiscall), passed in Debug and Release.

**x64:** LLVM 22.1.8 / clang-cl, sanitizer runtime validation, instrumented build, and AMD64 PE check passed. The ASan/UBSan libFuzzer campaign ran **301 seconds**, processing **7,235,656 units** (**24,038 average executions/second**), adding **2,710 corpus units**. Final libFuzzer metrics: **942 coverage counters, 1,958 features, 806 corpus units / 3,072 bytes**; peak RSS **535 MB**. The downloaded `campaign.log` was inspected; campaign exited successfully without ASan/UBSan diagnostic or crash reproducer. Artifact upload completed.

The fuzzer does not execute arbitrary mutated bytes as code. x64 tests invoking real trampolines and exercising exception/unwind behavior run independently in the x64 Debug/Release CTest suite.

## Source-level failure-path review

Reviewed paths include attach-state ownership, registry-capacity reservation, relocation, trampoline protection/flush, x64 function-table registration, thread suspension/context checks, target patch transaction rollback, detach, and unregister retry.

Important invariants observed:
- Unpublished attach state stays owned until patch and registry transition commit.
- x64 unwind table registration occurs before target patch publication.
- State destructor attempts unregister before freeing allocation; failure is fail-fast, not a silent free while the OS may consult the table.
- Target patch writes are transactional; rollback uncertainty is fail-fast.
- Unregister failure attempts to restore entry patch and retains retryable ownership.
- Strict thread policy rejects enumeration, suspension, or context-query failures.

This is source review, not a substitute for exercising every Windows API failure branch under deterministic injection. Existing patch-write tests do inject protect/flush outcomes; the missing gate is coverage of the real Win32 API wrappers and all lifecycle edges.

## Workflow behavior

- Full CI runs relevant pull requests, main pushes, manual dispatch, and weekly schedule. Version-tag publication is guarded separately.
- Focused native-hook workflow runs on PRs, manual dispatch, and schedule; x64 uses Clang libFuzzer + ASan/UBSan and x86 uses MSVC randomized stress.
- Both workflow files contain `workflow_dispatch` on the PR branch; default branch also has the native-hook workflow path with `workflow_dispatch`.
- Exact-head PR-triggered runs completed successfully. The UI-specific “Workflow dispatch unavailable” message was not reproduced; diagnosis requires exact Actions UI workflow entry/ref.

## Remaining acceptance gates

1. Deterministic Windows API failure injection for allocation, `VirtualProtect`, `FlushInstructionCache`, `RtlAddFunctionTable`, `RtlDeleteFunctionTable`, thread enumeration/suspend/context, and rollback paths.
2. Real host admission/drain/unload integration covering every direct target entry, callback, raw trampoline, and escaped callable reference.
3. Independent review of every failure edge and ownership transition.
4. Full exact-head Windows matrix and native-hook fuzz/stress rerun after code changes to these paths.

## Status

Architecture-level x86/x64 build/runtime tests, Detours integration, quality gates, and focused x86/x64 stress/fuzz are **PASS**. Production host-wide call admission/drain and complete deterministic API failure injection remain **OPEN**.

PR #7 remains draft and unmerged. Issue #6 remains open. No release/tag was created. Do not close Issue #6 or merge PR #7 until the remaining gates are completed or explicitly accepted.
