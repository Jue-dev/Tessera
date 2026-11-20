# Building Tessera

## Prerequisites

- **OS**: Windows 10 / 11 (x64 or x86)
- **Compiler**: MSVC 19.38+ (Visual Studio 2022 17.8+ or Build Tools 18+) with `/std:c++23preview` or `/std:c++latest`
- **Build System**: CMake 3.28+ and Ninja

## Configure, Build, and Test via CMake Presets

From a Visual Studio Developer Prompt (`vcvars64.bat` for x64 or `vcvarsamd64_x86.bat` for x86):

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug
```

Available presets:
- `x64-debug`
- `x64-release`
- `x86-debug`
- `x86-release`
- `x64-asan` (optional sanitizer configuration)
- `x64-analyze` (optional MSVC static-analysis configuration)

## Installing the SDK

```powershell
cmake --install artifacts/x64/Release/build --prefix artifacts/x64/Release/install
```

Downstream projects can then consume Tessera via:

```cmake
find_package(Tessera CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE tessera::tessera)
```

## Benchmarks

Benchmark targets are opt-in and do not replace correctness tests. Configure and build them separately:

```powershell
cmake -S . -B build-bench -G Ninja -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_BUILD_BENCH=ON
cmake --build build-bench --target tessera_bench tessera_decoder_bench tessera_pe_bench
.\build-bench\verify\bench\tessera_bench.exe
.\build-bench\verify\bench\tessera_decoder_bench.exe
.\build-bench\verify\bench\tessera_pe_bench.exe
```

- `tessera_bench`: pattern scan and RTTI/Python discovery.
- `tessera_decoder_bench`: bounded x64 instruction decoding.
- `tessera_pe_bench`: deterministic PE32+ raw-image parsing and accessors.

## Workspace helper scripts

- `scripts/clean.ps1` is the canonical workspace cleanup implementation; use `-DryRun` to preview removals. `scripts/clean.bat` remains as a thin Command Prompt compatibility entry point.
- `scripts/export_sdk.ps1` is the canonical SDK export implementation; `scripts/export_sdk.bat` remains as a thin Command Prompt compatibility entry point. The README's Windows quick-start commands intentionally use these wrappers so they work from both PowerShell and classic Command Prompt workflows.

## Fuzz targets

Fuzz harnesses are optional and are excluded from the normal SDK build. Configure a standalone build with:

```powershell
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_BUILD_FUZZ=ON -DTESSERA_ENABLE_LIBFUZZER=OFF
cmake --build build-fuzz --target tessera_fuzz_pe tessera_fuzz_json tessera_fuzz_pattern tessera_fuzz_profile_json tessera_fuzz_rtti_discovery
```

This standalone mode is useful for deterministic harness smoke checks; it does not enable coverage-guided fuzzing. For Clang/libFuzzer with ASan/UBSan, configure with a Clang toolchain and set both `TESSERA_ENABLE_LIBFUZZER=ON` and `TESSERA_STATIC_RUNTIME=ON` (the Windows LLVM runtime requires `/MT`). On native MSVC x86, use `TESSERA_ENABLE_MSVC_FUZZER=ON` (and `TESSERA_ENABLE_ASAN=ON`) because the distributed Windows LLVM package does not provide the i386 libFuzzer archive. The exact Windows x86/x64 campaign setup, runtime checks, duration controls, and artifact collection are maintained in [native-hook-fuzz.yml](../.github/workflows/native-hook-fuzz.yml); its PowerShell steps live under [native-hook-fuzz scripts](../.github/scripts/native-hook-fuzz/).

The seed corpora are checked in under `verify/fuzz/corpus/`. See [the fuzz guide](../verify/fuzz/README.md) for target coverage and campaign details.
