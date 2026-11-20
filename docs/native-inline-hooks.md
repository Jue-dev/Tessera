# Native inline hooks (Windows x86/x64)

Tessera provides a native inline-hook backend alongside Microsoft Detours.
It supports explicitly validated x86/x64 instruction layouts and fails closed
when it cannot safely decode, relocate, patch, or restore a target.

## Lifecycle and safety

- Entry writes use a rollback-capable transaction and instruction-cache flush.
- x64 trampolines register translated runtime unwind metadata before publishing
  the entry patch. Unsupported unwind layouts are rejected.
- CET/IBT landing pads are recognized and preserved.
- `Hook::acquire()` provides a lock-backed callable lease. Install/remove waits
  for leased calls to drain. `original()` remains a raw, non-owning pointer and
  requires host-side admission/drain.
- Thread-policy snapshots do not stop concurrent thread creation. Strict,
  best-effort, and no-suspension modes have different safety guarantees; none
  substitutes for host quiescence.

## Current CI and fuzz validation

Latest exact-head validation: commit
`fb2fdc84dd409b3e8d52c9b04afd1008acf5d041`.

- [Full CI matrix](https://github.com/Jue-dev/Tessera/actions/runs/44736486572):
  x64/x86 Debug and Release, full CTest (13/13 suites per configuration),
  Detours x64/x86, MSVC `/analyze`, and `/GR-` quality gate passed.
- The quality gate consumed all six checked-in fuzz corpora with `-runs=100`,
  ran all three benchmark targets, and completed SDK install/package checks.
- [Native-hook fuzz campaigns](https://github.com/Jue-dev/Tessera/actions/runs/44736487041):
  x86 MSVC Fuzzer + ASan completed 3,916,127 executions / 301 seconds;
  x64 LLVM libFuzzer + ASan/UBSan completed 7,059,226 executions / 301 seconds.
  No crash or sanitizer finding was reported.
- x64 trampoline unwind extraction into `native_unwind.cpp` was compiled and
  covered by the exact-head matrix.

These are exact-head CI and fuzz results, not a blanket production-safety
certification. Remaining fault-injection, page-protection recovery, cross-image
coordination, and concurrency-boundary work is tracked in
[Issue #24](https://github.com/Jue-dev/Tessera/issues/24).

## Architecture decision record

See [ADR 0002](adr/0002-native-inline-hook-safety-contract.md) for the safety
contract, supported boundaries, and validation caveats.
