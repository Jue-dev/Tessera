# Tessera fuzz targets

The harnesses expose `LLVMFuzzerTestOneInput` for JSON parsing/writing, profile and target-profile JSON deserialization, byte-pattern parsing/search, PE parsing, RTTI type-descriptor/string discovery over `FakeMemoryBackend`, and (on Windows) native inline-hook instruction decoding/relocation and attach/detach lifecycle validation.

## Native-hook Windows validation

The native-hook validation workflow has two independent jobs. They are intentionally separate so a successful x86 run cannot hide a failed or skipped x64 campaign, and vice versa.

- **x64:** Clang `libFuzzer` with production-module coverage instrumentation, AddressSanitizer, and UndefinedBehaviorSanitizer. The job verifies the Clang runtime libraries, the generated executable's PE machine (`AMD64 / 0x8664`), non-empty seed corpus, and non-zero executed-input statistics.
- **x86:** MSVC's coverage-guided Fuzzer + AddressSanitizer builds and runs a real 32-bit executable (`I386 / 0x014c`). It validates the runtime probe, architecture, ASan DLL, execution count, campaign duration, and non-zero feature coverage. The Windows i386 distribution does not provide LLVM libFuzzer archive support, so this job uses MSVC Fuzzer.

## Standalone smoke mode

With `TESSERA_BUILD_FUZZ=ON` and `TESSERA_ENABLE_LIBFUZZER=OFF`, the fuzz targets keep standalone entry points and can run without the LLVM libFuzzer runtime. Standalone mode is useful for deterministic regression and stress checks; it is not a substitute for sustained coverage-guided fuzzing.

## Seed corpus and bounded campaign

The native-hook seed corpus lives in `verify/fuzz/corpus/native_hook`. The manual workflow supports campaigns of 300, 600, or 900 seconds (300 seconds by default). The weekly schedule runs 300 seconds on each architecture. Both architecture jobs upload logs, corpus, and crash artifacts.

## LLVM libFuzzer mode

Use a Clang toolchain that provides the Windows libFuzzer, ASan, and UBSan runtimes:

```powershell
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_CXX_STANDARD=23 -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_BUILD_FUZZ=ON -DTESSERA_STATIC_RUNTIME=ON -DTESSERA_ENABLE_LIBFUZZER=ON
cmake --build build-fuzz --target tessera_fuzz_native_hook
```

The libFuzzer target instruments the production modules, not only the small harness entry point. On Windows Clang, the build uses the static CRT and disables incremental linking for the fuzz targets.
