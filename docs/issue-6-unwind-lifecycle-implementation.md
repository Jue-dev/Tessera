# Issue #6 — native hook implementation and verified status

This record covers Tessera's Windows x86/x64 native inline-hook backend,
x64 trampoline unwind metadata, callable lifetime, and exact-head validation.
See [the comprehensive review](issue-6-audit-findings.md) and
[acceptance checklist](issue-6-ci-validation-checklist.md).

## Implemented behavior

- x64 trampoline unwind metadata is generated and registered before publishing
  the target entry patch.
- Supported v1 unwind operations are validated and mapped only at relocated
  instruction boundaries. Unsupported handler/chained records, unsupported
  opcodes/versions, malformed slot streams, unmappable offsets, non-entry
  targets, and unsupported prologues fail closed.
- Source runtime-function and unwind data are checked for bounds/readability;
  stolen prologues cannot extend outside the source function.
- Targets with no runtime-function record are accepted only for a small audited
  stack-neutral leaf-instruction subset.
- Detach/unregister failure restores/reinstalls the entry patch when possible
  and preserves retryable token/trampoline/table ownership. Unrecoverable
  rollback does not report success.
- `Hook::acquire()` supplies a non-copyable, non-movable, thread-affine
  callable lease. `original()` remains raw/non-owning; direct users must
  provide host admission and drain.
- x86 ABI tests exercise stdcall, fastcall, and thiscall through target,
  detour, and trampoline, including stack balance and restoration.
- Regression coverage includes relocation/branch cases, x64 unwind operation
  and slot variants, malformed metadata, exception unwinding, rollback,
  unregister retry, and controlled DLL admission/drain/detach/unload.

## Exact-head validation

### Native-hook campaigns

[Run #74 / 44619644521](https://github.com/Jue-dev/Tessera/actions/runs/44619644521)
passed on commit `f3b40519`.

- **x86:** MSVC Fuzzer + ASan; 301 sec, 5,117,733 executions, 1,151 features,
  303 corpus units / 1,369 bytes, peak RSS 523 MB.
- **x64:** LLVM libFuzzer + ASan/UBSan; 301 sec, 4,790,089 executions,
  942 coverage counters, 1,956 features, 811 corpus units / 3,066 bytes,
  peak RSS 531 MB.
- Neither campaign reported a crash or sanitizer finding.

The native fuzzer validates instruction decoding/relocation setup, attach/detach,
and restoration; it does not execute arbitrary fuzz-generated trampolines.

### Full Windows CI

[Run #74 / 44619644508](https://github.com/Jue-dev/Tessera/actions/runs/44619644508)
failed CTest on commit `f3b40519`. Failures:

- x86 remote-process region enumeration;
- resolver test's non-portable `SIZE_MAX` instruction-length expectation;
- branching virtual-base RTTI fixture on both architectures.

Diagnostics and corrections are in progress. **Fuzz success is not a full CI
pass and does not satisfy the merge gate.**

## Remaining acceptance obligations

- Host admission/drain for direct target calls and detour module lifetime.
- Deterministic failure injection for Win32 thread, patch, cache, protection,
  and unwind-table operations.
- Protection-restore recovery semantics for `MemoryWriter`.
- Expanded semantic tests for the custom decoder and supported relocation set.
- Cross-image registry and concurrent thread-creation contract.
- Final exact-head full CI and native campaigns, plus independent review.
