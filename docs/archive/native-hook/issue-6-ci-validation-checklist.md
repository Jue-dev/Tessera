# Issue #6 — Windows x86/x64 validation and acceptance checklist

**Current reviewed commit:** `f3b40519db8e27e9d783c965b4681e3494b249e8`  
**PR #7:** open, draft, not merged. **Issue #6:** open.

## 1. Exact-head evidence

- [x] x86 MSVC Fuzzer + ASan executable built and PE machine verified as I386.
- [x] x64 LLVM libFuzzer + ASan/UBSan executable built and PE machine verified as AMD64.
- [x] Both sustained coverage-guided campaigns completed their requested 301 seconds.
- [ ] Full Windows CI matrix green on the current source head.
- [ ] All current runtime failures diagnosed and corrected.

### Native Hook campaign

[Run #74 / 44619644521](https://github.com/Jue-dev/Tessera/actions/runs/44619644521) — both jobs passed.

- x86: 301 sec, 5,117,733 executions, 1,151 features, corpus 303/1,369 bytes, peak RSS 523 MB.
- x64: 301 sec, 4,790,089 executions, 942 coverage counters, 1,956 features, corpus 811/3,066 bytes, peak RSS 531 MB.
- No crash or sanitizer report.

### Full CI

[Run #74 / 44619644508](https://github.com/Jue-dev/Tessera/actions/runs/44619644508) — failed CTest.

- x64 Debug/Release: process-memory, resolver, patch-hook, infra, profile/target, RTTI suites passed; deep-validation failed.
- x86 Debug/Release: process-memory, resolver, deep-validation failed; other suites passed.
- Detours x64: deep-validation failed.
- Detours x86: process-memory, resolver, deep-validation failed.
- Static analysis and no-RTTI quality gates were still running when this status was recorded; final job conclusions must be checked before updating this ledger.

## 2. Runtime failures to resolve

- [ ] **x86 remote process region enumeration:** full-address-space `enumerate_regions` fails; x64 passes. Add underlying native error diagnostics and investigate target maximum-address/WOW64 behavior. Do not weaken the test to a narrow range without understanding the failure.
- [ ] **Resolver invalid-length test:** the previous test used `SIZE_MAX`, which is valid as a 32-bit `size_t` on x86. Replace it with an architecture-independent invalid displacement/instruction-length pair.
- [ ] **Branching virtual-base RTTI fixture:** `RttiCatalog::discover_all` fails on both x86 and x64. Add the underlying error to the test output and diagnose the fixture/catalog path.

## 3. Code-review regression checks

- [x] Destructor consumes the `[[nodiscard]]` status explicitly while diagnostics remain.
- [x] Requested atomic-file backup cannot silently degrade to an unbacked replacement.
- [ ] Execute-only memory is not classified as readable; fake backend enforces read permission and a regression test is added.
- [ ] Reserved instruction encodings fail closed in the custom decoder.
- [ ] Routine fuzz diagnostics are normalized to non-error output in Actions.
- [x] MSVC Fuzzer coverage validation uses its `ft:` feature summary.
- [x] Stale/duplicate resolver and RTTI test code corrected.
- [x] Unimplemented CMake `TESSERA_USE_STD_MODULE` option removed.

## 4. Production acceptance gates

- [ ] Host-side admission control and drain for direct target calls/detour lifetime.
- [ ] Exhaustive deterministic failure injection for suspend/context, patch write/rollback, cache flush, protection restoration, and unwind-table registration/unregistration.
- [ ] Review `MemoryWriter` protection-restore warning semantics and retry/recovery ownership.
- [ ] Expand supported-instruction semantic tests; fuzz-generated trampolines are not executed.
- [ ] Verify cross-image backend copies and thread-creation races are explicitly documented.
- [ ] Final exact-head full CI and native campaigns pass.
- [ ] Independent review and PR/Issue acceptance ledger updated.

**Do not merge while runtime failures or production acceptance gates remain open.**
