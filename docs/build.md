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
- `x64-bench` (opt-in benchmark build)
- `x64-fuzz-smoke` (standalone fuzz harnesses for deterministic corpus replay)

## Installing the SDK

```powershell
cmake --install artifacts/x64/Release/build --prefix artifacts/x64/Release/install
```

Downstream projects can then consume Tessera via:

```cmake
find_package(Tessera CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE tessera::tessera)
```

## CMake configuration options and supported reduced builds

The default developer configuration enables tests and examples, keeps benchmarks and
fuzz harnesses opt-in, and enables the profile, target-profile, and logging SDK
components. The CI reduced-configuration matrix disables tests and examples for
all reduced SDK variants, then builds, installs, and compiles a separate
`find_package(Tessera CONFIG REQUIRED)` consumer against each installed package.

| CI variant | Options changed from the reduced-build baseline |
| --- | --- |
| `minimal` | `TESSERA_BUILD_PROFILE=OFF`, `TESSERA_BUILD_TARGETS=OFF`, `TESSERA_BUILD_LOGGING=OFF` |
| `no-profile` | `TESSERA_BUILD_PROFILE=OFF` |
| `no-targets` | `TESSERA_BUILD_TARGETS=OFF` |
| `no-logging` | `TESSERA_BUILD_LOGGING=OFF` |

The reduced-build baseline also sets `TESSERA_BUILD_TESTS=OFF` and
`TESSERA_BUILD_EXAMPLES=OFF`. The regular x86/x64 Debug/Release CI jobs exercise
the default test/example-enabled build; the quality gate separately enables
benchmark and fuzz targets.

Important options and constraints:

- `TESSERA_BUILD_TESTS` and `TESSERA_BUILD_EXAMPLES` control their respective
  verification and sample subdirectories.
- `TESSERA_BUILD_BENCH` and `TESSERA_BUILD_FUZZ` are opt-in and add the
  verification subdirectory even when tests are disabled.
- `TESSERA_BUILD_PROFILE`, `TESSERA_BUILD_TARGETS`, and
  `TESSERA_BUILD_LOGGING` independently remove optional SDK components.
- `TESSERA_WITH_DETOURS=ON` requires Microsoft Detours headers and a compatible
  library; configuration fails when the dependency is unavailable.
- `TESSERA_ENABLE_LIBFUZZER=ON` requires `TESSERA_STATIC_RUNTIME=ON` on
  Windows. The LLVM fuzzer runtime does not support the dynamic `/MD` runtime.
- `TESSERA_ENABLE_MSVC_FUZZER=ON` requires native MSVC,
  `TESSERA_ENABLE_ASAN=ON`, and `TESSERA_STATIC_RUNTIME=ON`; it cannot be
  enabled together with `TESSERA_ENABLE_LIBFUZZER`.
- `TESSERA_ENABLE_ANALYZE` enables MSVC static analysis and is exercised by a
  dedicated CI job rather than a reduced package variant.

Example minimal installed SDK build:

```powershell
cmake -S . -B build-minimal -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF `
  -DTESSERA_BUILD_PROFILE=OFF -DTESSERA_BUILD_TARGETS=OFF `
  -DTESSERA_BUILD_LOGGING=OFF
cmake --build build-minimal --parallel
cmake --install build-minimal --prefix install-minimal
```

The four CI variants are representative supported configurations, not an
exhaustive Cartesian product of every CMake option. Dependency-specific
Detours and fuzzer toolchain combinations are validated by their dedicated
integration/quality workflows.

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

- `scripts/clean.ps1` is the workspace cleanup entry point; use `-DryRun` to preview removals.
- `scripts/export_sdk.ps1` builds and exports the SDK. The redundant `.bat` forwarding wrappers were removed; invoke these PowerShell scripts from a PowerShell prompt.

## Fuzz targets

Fuzz harnesses are optional and are excluded from the normal SDK build. Configure a standalone build with:

```powershell
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_BUILD_FUZZ=ON -DTESSERA_ENABLE_LIBFUZZER=OFF
cmake --build build-fuzz --target tessera_fuzz_pe tessera_fuzz_json tessera_fuzz_pattern tessera_fuzz_profile_json tessera_fuzz_rtti_discovery
```

This standalone mode is useful for deterministic harness smoke checks; it does not enable coverage-guided fuzzing. For Clang/libFuzzer with ASan/UBSan, configure with a Clang toolchain and set both `TESSERA_ENABLE_LIBFUZZER=ON` and `TESSERA_STATIC_RUNTIME=ON` (the Windows LLVM runtime requires `/MT`). On native MSVC x86, use `TESSERA_ENABLE_MSVC_FUZZER=ON` (and `TESSERA_ENABLE_ASAN=ON`) because the distributed Windows LLVM package does not provide the i386 libFuzzer archive. The exact Windows x86/x64 campaign setup, runtime checks, duration controls, and artifact collection are maintained in [native-hook-fuzz.yml](../.github/workflows/native-hook-fuzz.yml); its PowerShell steps live under [native-hook-fuzz scripts](../.github/scripts/native-hook-fuzz/).

The seed corpora are checked in under `verify/fuzz/corpus/`. See [the fuzz guide](../verify/fuzz/README.md) for target coverage and campaign details.


## Benchmark and fuzz-smoke presets

The dedicated presets keep optional tools out of the default SDK build:

```powershell
# Build the benchmark executables
cmake --preset x64-bench
cmake --build --preset x64-bench
 .\artifacts\x64\Bench\build\verify\bench\tessera_bench.exe
 .\artifacts\x64\Bench\build\verify\bench\tessera_decoder_bench.exe
 .\artifacts\x64\Bench\build\verify\bench\tessera_pe_bench.exe

# Build standalone fuzz harnesses (no libFuzzer runtime)
cmake --preset x64-fuzz-smoke
cmake --build --preset x64-fuzz-smoke
```

Replay each harness against its matching seed directory with `-runs=100`:

| Harness | Corpus |
| --- | --- |
| `tessera_fuzz_pattern` | `verify/fuzz/corpus/pattern` |
| `tessera_fuzz_pe` | `verify/fuzz/corpus/pe` |
| `tessera_fuzz_json` | `verify/fuzz/corpus/json` |
| `tessera_fuzz_profile_json` | `verify/fuzz/corpus/profile_json` |
| `tessera_fuzz_python_bridge` | `verify/fuzz/corpus/python_bridge` |
| `tessera_fuzz_scanner` | `verify/fuzz/corpus/scanner` |
| `tessera_fuzz_rtti_discovery` | `verify/fuzz/corpus/rtti_discovery` |
| `tessera_fuzz_native_hook` (Windows) | `verify/fuzz/corpus/native_hook` |

Run the fuzz executables from the repository root so the corpus paths above resolve. The native-hook harness is generated only on Windows. For coverage-guided campaigns, use the dedicated Clang/libFuzzer or MSVC-fuzzer configuration documented in [the fuzz guide](../verify/fuzz/README.md); the standalone preset is a deterministic smoke/replay configuration, not a substitute for those campaigns.
