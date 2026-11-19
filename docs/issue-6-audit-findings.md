# Issue #6 — Comprehensive review findings

**Review scope:** PR #7, native inline hooks, x86/x64 validation, process/memory APIs,
patch transactions, test infrastructure, CMake, and CI workflows.

## Evidence reviewed

- Native-hook workflow run **44619644521** on commit `f3b40519db8e27e9d783c965b4681e3494b249e8`: both architecture campaigns passed.
- Full CI run **44619644508** on the same commit: failed CTest in three areas; details below.
- Previous campaign run **44617792559**: x64 passed; x86 completed its 301-second campaign but failed an incorrect coverage-output assertion. That assertion was corrected in commit `a8834b6`.
- Current branch is still a draft PR; no merge or release validation is implied.

## Confirmed findings and fixes in this review revision

| Priority | Finding | Resolution |
|---|---|---|
| P1 | `Patch::~Patch` discarded a `[[nodiscard]]` status under `/WX` | Explicitly consume the destructor-only status; diagnostics remain in the helper. |
| P1 | `AtomicFileWriter` could replace an existing file without creating a requested backup when `ReplaceFileW` failed | Fail without replacing the original when a backup was requested and cannot be created; add a backup-content test. |
| P1 | Execute-only Windows regions were classified as readable | Remove `Execute` from read permission checks; make the fake backend enforce read permissions; add regression coverage. |
| P1 | Resolver overflow test used a value that is valid on 32-bit `size_t` | Test an invalid displacement/instruction-length combination portable across x86/x64. |
| P1 | RTTI tests had namespace mistakes and duplicated ObjectView tests | Correct namespace usage and remove duplicate cases. |
| P1 | x86 MSVC Fuzzer output uses `ft:`, not LLVM libFuzzer's `cov:` | Validate the MSVC feature summary and probe output. |
| P2 | Routine fuzzer diagnostics were emitted through stderr and displayed red in Actions | Convert merged output to ordinary strings before teeing it to the live log/artifact. |
| P2 | CMake exposed `TESSERA_USE_STD_MODULE` without an implementation | Remove the misleading unused option. |
| P2 | Decoder did not explicitly reject reserved `0F 0C` | Reject rather than guess an instruction length; add a regression test. |

These changes must be confirmed by the next exact-head CI run before being considered closed.

## Runtime test failures on commit `f3b40519`

### x86 — remote process region enumeration

`Remote process integration with tessera_test_host` fails when the test enumerates
the entire target address space. The same test passes x64. The test currently
does not print the underlying `Error`; the next revision adds native error,
operation, and detail diagnostics.

Do not weaken this test to a small range until the underlying failure is
understood. The process address-space maximum and x86/WOW64 behavior are under
review.

### Resolver — portable invalid-length test

The second test used `SIZE_MAX` as instruction length. On x86, `SIZE_MAX` is
32-bit and can be a valid signed 64-bit offset after conversion; the test was
not architecture-independent. Replace it with a displacement offset that
actually exceeds the supplied instruction length.

### Deep validation — virtual branching RTTI fixture

The x86 and x64 fixture test fails at `RttiCatalog::discover_all`. The test
currently hides the underlying error. The next revision adds diagnostic output
before the assertion. This remains unresolved until the error is identified and
the fixture/catalog test passes on both architectures.

## Open stability gates

1. **Host call admission/drain:** thread snapshots are not a barrier against new
   thread creation or direct calls into the patched target. Production use
   requires host-side admission control and drain; `original()` remains a raw,
   non-owning pointer outside the callable lease.
2. **Memory protection recovery:** `MemoryWriter` reports protection-restore
   warnings but may leave pages with elevated protection. Retry/recovery and
   ownership of the previous protection need a dedicated fault-injection design.
3. **Win32 failure injection:** deterministic failures for suspend/context,
   protection, instruction-cache flush, and dynamic function-table registration
   are not yet exhaustive.
4. **Fuzz semantics:** the native-hook fuzzer validates decoding, relocation
   setup, attach/detach, and restoration; it intentionally does not execute
   fuzz-generated instruction bytes or generated trampolines. Curated executable
   relocation tests cover supported semantic cases, but differential/random
   execution is not yet a release gate.
5. **Decoder support envelope:** the custom decoder is bounded and fail-closed
   for many unsupported forms, but it is not a complete ISA decoder. The
   supported instruction set and invalid-encoding corpus need continued
   expansion.
6. **Cross-image coordination:** the native-hook registry and process-wide lock
   protect copies sharing the same backend image; independent copies of Tessera
   in different modules are not a universal registry.
7. **Build-option matrix:** optional modules and reduced test/example
   configurations need a separate CMake matrix beyond the current default CI.

## Exact-head validation status

- x86 coverage-guided ASan campaign: **PASS**, 301 seconds, 5,117,733 executions,
  1,151 features, 303 corpus units / 1,369 bytes, 523 MB peak RSS.
- x64 coverage-guided ASan/UBSan campaign: **PASS**, 301 seconds, 4,790,089
  executions, 942 coverage counters, 1,956 features, 811 corpus units /
  3,066 bytes, 531 MB peak RSS.
- Full CTest matrix on `f3b40519`: **FAIL** because the x86 remote-region and
  resolver tests fail, and the virtual-branching RTTI fixture fails on both
  architectures. Diagnostics and corrections are in progress.
- PR remains draft/unmerged.
