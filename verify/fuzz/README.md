# Tessera fuzz targets

The eight harnesses expose LLVMFuzzerTestOneInput for pattern parsing/search, PE parsing (including file backend, checksum, and code-cave boundaries), JSON parsing/writing, profile and target-profile deserialization, Python bridge metadata, scanner input, RTTI discovery, and native-hook instruction decoding/relocation and lifecycle validation.

## Continuous campaigns

The consolidated workflow is .github/workflows/fuzz.yml. It retains the eight-target continuous matrix and the separate native-hook x86/x64 campaign. Pull-request path triggers cover CMake, source, public headers, fuzz/test code, hook code, setup action, and the consolidated workflow/script. Both original schedules and manual dispatch remain enabled.

- Continuous targets: tessera_fuzz_pe, tessera_fuzz_json, tessera_fuzz_pattern, tessera_fuzz_profile_json, tessera_fuzz_python_bridge, tessera_fuzz_scanner, tessera_fuzz_rtti_discovery, and tessera_fuzz_native_hook. Each uses its matching checked-in corpus.
- Native-hook x64: LLVM libFuzzer with production-module coverage, ASan, and UBSan; the workflow verifies Clang runtime files and AMD64 output.
- Native-hook x86: MSVC coverage-guided Fuzzer with ASan; the workflow checks the I386 executable, runtime probe, staged ASan DLL, executions, duration, and coverage features.

Native-hook stages use .github/scripts/fuzz-native-hook.ps1 with Stage setup/build/run and Arch x64/x86. Campaign outputs, corpora, and crash artifacts are uploaded even when a campaign fails.

## Standalone corpus replay

With TESSERA_BUILD_FUZZ=ON and TESSERA_ENABLE_LIBFUZZER=OFF, each harness uses fuzz_corpus_runner.hpp to enumerate its seed corpus in stable order and invoke the same fuzz callback. The x64-fuzz-smoke preset registers CTest replay tests:

    cmake --preset x64-fuzz-smoke
    cmake --build --preset x64-fuzz-smoke
    ctest --preset x64-fuzz-smoke --output-on-failure
    .\scripts\run-fuzz-smoke.ps1

Standalone replay is deterministic regression coverage, not a substitute for sustained coverage-guided campaigns.

## Corpus structure and dependencies

Seed corpora are in verify/fuzz/corpus/: pattern, pe, json, profile_json, python_bridge, scanner, rtti_discovery, and native_hook. Native-hook campaigns support 300, 600, or 900 seconds; continuous campaigns support 30, 60, 120, or 300 seconds per target.

The LLVM/libFuzzer runtime is test-only. Windows x64 requires a Clang distribution with libFuzzer/ASan/UBSan; native MSVC x86 uses the MSVC fuzzer because the Windows i386 LLVM archive does not provide the needed libFuzzer library. See docs/development-workflow.md and docs/safety-and-boundaries.md.
