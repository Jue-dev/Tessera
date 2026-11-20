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

## Fuzz validation

The PR workflow runs independent x86 and x64 coverage-guided campaigns:

- x86: MSVC Fuzzer + ASan, 32-bit PE (`I386 / 0x014c).
- x64: LLVM libFuzzer + ASan/UBSan, 64-bit PE (`AMD64 / 0x8664`).

Exact-head campaign results on commit `f3b40519`:

| Architecture | Duration | Executions | Coverage | Peak RSS | Result |
|---|---:|---:|---:|---:|---|
| x86 | 301 sec | 5,117,733 | 1,151 features | 523 MB | PASS |
| x64 | 301 sec | 4,790,089 | 942 counters / 1,956 features | 531 MB | PASS |

No crash or sanitizer report was produced by either campaign. These fuzz
campaigns validate the instrumented attach/detach lifecycle and restoration;
they do not execute arbitrary fuzz-generated trampolines.

## Current validation status

The fuzz jobs above passed on `f3b40519`. Full CTest did not yet pass on that
commit: x86 remote process region enumeration, a resolver invalid-length test,
and the x86/x64 branching-virtual-base RTTI fixture failed. See
`docs/issue-6-audit-findings.md` for details and the next diagnostic steps.

**This PR is still draft. Do not merge based on fuzz success alone.**


## Architecture decision record

The safety and lifecycle contract summarized above is recorded in [ADR 0002](adr/0002-native-inline-hook-safety-contract.md). The ADR captures design decisions; exact-head CI results and outstanding acceptance gates remain tracked in the Issue #6 audit and validation checklist.
