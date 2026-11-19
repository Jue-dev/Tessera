# Windows native inline hooks — validation and safety status

The Windows validation workflows separate general architecture/runtime validation from focused native-hook stress:

- `.github/workflows/ci.yml` runs x86/x64 Debug and Release, CTest, SDK staging, Microsoft Detours integration on both architectures, the `/GR-` quality gate, MSVC static analysis, and release packaging behind a version-tag guard.
- `.github/workflows/native-hook-fuzz.yml` runs focused native-hook stress on pull requests, manual dispatch, and schedule. x64 uses Clang libFuzzer with ASan/UBSan. x86 uses MSVC randomized attach/detach stress; it is not coverage-guided fuzzing.
- The default branch and Issue #6 PR branch contain the native-hook workflow path with `workflow_dispatch`. PR-triggered workflows have completed successfully; the UI-only dispatch-unavailable message was not reproduced.

## Latest validation

Tested C++ source commit: `1cad6ef8095020219a89a7d5bf255228f21f7b77`. Latest documentation-only PR head: `6586750f2faa8683ad90e7fc87e697c30dd19be1`.

- [CI run #58](https://github.com/Jue-dev/Tessera/actions/runs/44603747013): all eight active jobs passed. x86/x64 Debug and Release each passed 10/10 CTest tests; Detours x86/x64, no-RTTI, static analysis, and install/package gates passed. Tag-only publication was skipped as expected.
- [Native-hook run #54](https://github.com/Jue-dev/Tessera/actions/runs/44603747347): both x86 and x64 jobs passed and artifacts uploaded.
- x86: **65,546 inputs; 60,497 successful attach/detach lifecycles; 3,783 ms; 17,326 inputs/second**. Separate x86 ABI tests execute stdcall/fastcall/thiscall targets, detours, and original trampolines in Debug and Release.
- x64: **301-second** libFuzzer ASan/UBSan campaign; **7,235,656 executions; 2,710 new corpus units; 942 coverage counters; 1,958 features; 806 corpus units / 3,072 bytes; 535 MB peak RSS**. Downloaded campaign log contains no sanitizer report/crash and ends with a successful DONE summary. Separate x64 CTest executes real trampolines and tests unwind/exception behavior.

The randomized x86 and coverage-guided x64 harnesses do not execute arbitrary mutated input bytes as native code. Real target/trampoline calls are covered by architecture-specific CTest suites.

## Remaining work before Issue #6 can close

- Deterministic Windows API failure injection for allocation, protection, instruction-cache flush, function-table registration/unregistration, thread operations, and rollback.
- Production-host integration proving every direct target entry, callback, raw trampoline pointer, and escaped callable use is stopped and drained before detach/unload.
- Independent reviewer audit of all failure paths and ownership transitions.
- Rerun full exact-head x86/x64 matrix and focused fuzz/stress after code changes to these paths.

The DLL fixture demonstrates one controlled admission/drain/detach/unload sequence; it does not prove production host gates every call path. Keep PR #7 draft/open and Issue #6 open until remaining acceptance work is complete or explicitly accepted.
