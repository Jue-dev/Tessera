# Windows native inline hooks — validation and safety status

The Windows validation workflows separate general architecture/runtime validation from focused native-hook stress:

- `.github/workflows/ci.yml` runs x86/x64 Debug and Release, CTest, SDK staging, Microsoft Detours integration on both architectures, the `/GR-` quality gate, MSVC static analysis, and release packaging behind a version-tag guard.
- `.github/workflows/native-hook-fuzz.yml` runs a focused native-hook job on pull requests, manual dispatch, and schedule. x64 uses Clang libFuzzer with ASan/UBSan. x86 uses an MSVC deterministic randomized attach/detach harness; this is not coverage-guided fuzzing.
- The default branch and the Issue #6 PR branch both contain the native-hook workflow path with a `workflow_dispatch` trigger. The PR-triggered workflow has been executed successfully; a separate UI-only dispatch-unavailable message was not reproduced by that run.

## Latest exact-head evidence

Validated source commit: `1cad6ef8095020219a89a7d5bf255228f21f7b77`.

- [CI run #57](https://github.com/Jue-dev/Tessera/actions/runs/44601445116): all eight active jobs passed. x86 and x64 Debug/Release each passed 10/10 CTest tests; Detours x86/x64, no-RTTI, static analysis, and packaging/install quality gates passed. Tag-only publication was skipped as expected.
- [Native-hook run #52](https://github.com/Jue-dev/Tessera/actions/runs/44601445007): x86 and x64 jobs both passed.
- x86: 65,546 randomized test inputs, 60,497 successful attach/detach lifecycles, 2,805 ms, 23,367 inputs/second. Separate x86 CTest ABI tests execute stdcall/fastcall/thiscall targets, detours, and original trampolines in Debug and Release.
- x64: 301-second libFuzzer ASan/UBSan campaign; 7,317,217 executed units, 2,754 new corpus units, 946 coverage counters, 1,961 features, 805 corpus units / 3,016 bytes, 537 MB peak RSS. No sanitizer report or crash appeared in the successful campaign log. Separate x64 CTest cases execute real trampolines and test unwind/exception behavior.

The randomized x86 and coverage-guided x64 harnesses do not execute arbitrary mutated input bytes as native code. Real target/trampoline calls are covered by architecture-specific CTest suites. Older Action runs from earlier commits must not be substituted for this exact-head evidence.

## Remaining work before Issue #6 can close

- Deterministic Windows API failure injection for allocation, protection, instruction-cache flush, function-table registration/unregistration, thread operations, and rollback.
- Real production-host integration proving every direct target entry, detour callback, raw trampoline pointer, and escaped callable use is stopped and drained before detach/unload.
- Independent reviewer audit of all failure paths and ownership transitions.
- Rerun the full exact-head x86/x64 matrix and focused fuzz/stress after any changes to these paths.

The DLL fixture demonstrates one controlled admission/drain/detach/unload sequence; it does not prove that the production host gates every possible call path. Keep PR #7 draft/open and Issue #6 open until the remaining acceptance work is complete or explicitly accepted.
