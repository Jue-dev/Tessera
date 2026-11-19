# Tessera fuzz targets

The harnesses expose `LLVMFuzzerTestOneInput` for JSON parsing/writing, byte-pattern parsing/search, PE parsing, and (on Windows) native inline-hook instruction decoding/relocation.

## Standalone smoke mode (default)

With `TESSERA_BUILD_FUZZ=ON` and `TESSERA_ENABLE_LIBFUZZER=OFF`, targets keep a small `main()` so they can run without the LLVM libFuzzer runtime. The native-hook executable submits focused branch/terminal/VEX/EVEX seeds and 512 fixed-seed random byte sequences through the real attach/detach path.

The Windows-only `tessera_fuzz_native_hook` target feeds up to 96 arbitrary bytes into an isolated executable page. It never executes the supplied bytes or generated trampoline. Rejected inputs are checked for failure-atomicity; accepted inputs must detach and restore original bytes. Standalone smoke is not a substitute for sustained coverage-guided fuzzing.

## Seed corpus and bounded campaign

The seed corpus lives in `verify/fuzz/corpus/native_hook`. The manual-only `Native Hook Coverage-Guided Fuzz` workflow supports 60, 300, and 900 seconds on Windows x64 with Clang libFuzzer, ASan, and UBSan. It copies the seeds into the runner workspace and uploads corpus/crash artifacts. No weekly schedule is enabled.

Current-head acceptance evidence (2026-11-19): [run #24](https://github.com/Jue-dev/Tessera/actions/runs/44566681404), exact commit `313d96f503ac835d602499b7350270d5198d71a0`, completed a 900-second campaign: 14,666,829 executions, 2,651 new units, 978 coverage counters, 1,999 features, no crash/sanitizer findings. The artifact was reviewed (797 corpus files, no crash files). This is x64 fuzz evidence; x86 remains covered by the Windows matrix, Detours integration, and deterministic smoke tests.

## LLVM libFuzzer mode

Use a Clang toolchain that provides the libFuzzer runtime:

```powershell
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=Release -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_BUILD_FUZZ=ON -DTESSERA_STATIC_RUNTIME=ON -DTESSERA_ENABLE_LIBFUZZER=ON
cmake --build build-fuzz --target tessera_fuzz_native_hook
.\scripts\run-final-validation.ps1 -RunFuzz -FuzzSeconds 300
```

The libFuzzer target instruments production modules with coverage, AddressSanitizer, and UndefinedBehaviorSanitizer. On Windows Clang use `/MT`; the build option enforces static CRT and disables incremental linking for the fuzz targets.