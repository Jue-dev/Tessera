# Tessera fuzz targets

The harnesses expose `LLVMFuzzerTestOneInput` for JSON parsing/writing, byte-pattern parsing/search, PE parsing, and (on Windows) native inline-hook instruction decoding/relocation.

## Standalone smoke mode (default)

With `TESSERA_BUILD_FUZZ=ON` and `TESSERA_ENABLE_LIBFUZZER=OFF`, the targets keep a small `main()` so they can run without the LLVM libFuzzer runtime. The native-hook executable does more than a single link/run check: it submits focused branch/terminal/VEX/EVEX seeds and 512 fixed-seed random byte sequences through the real attach/detach path.

The Windows-only `tessera_fuzz_native_hook` target feeds up to 96 arbitrary bytes into an isolated executable page. It never executes the supplied instruction bytes or the generated trampoline. Rejected inputs are checked for failure-atomicity; accepted inputs must detach and restore all original bytes. The standalone corpus is deterministic (seed `0xC0FFEE42`) so a CI failure can be reproduced exactly. The known-good seed must complete at least one attach/detach lifecycle or the executable fails.

Standalone smoke mode is still not a substitute for a sustained coverage-guided fuzzing campaign.

## LLVM libFuzzer mode

Use a Clang toolchain that provides the libFuzzer runtime:

```powershell
cmake -S . -B build-fuzz -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DTESSERA_BUILD_TESTS=OFF `
  -DTESSERA_BUILD_EXAMPLES=OFF `
  -DTESSERA_BUILD_FUZZ=ON `
  -DTESSERA_STATIC_RUNTIME=ON `
  -DTESSERA_ENABLE_LIBFUZZER=ON
cmake --build build-fuzz
.\build-fuzz\verify\fuzz\tessera_fuzz_json.exe -max_total_time=60
.\build-fuzz\verify\fuzz\tessera_fuzz_pattern.exe -max_total_time=60
.\build-fuzz\verify\fuzz\tessera_fuzz_pe.exe -max_total_time=60
.\build-fuzz\verify\fuzz\tessera_fuzz_native_hook.exe -max_total_time=300
```

In libFuzzer mode the harness `main()` functions are disabled, LLVM supplies the driver, and the production Tessera object libraries are compiled with fuzzer coverage plus AddressSanitizer and UndefinedBehaviorSanitizer instrumentation. The default smoke mode remains available to MSVC users without the LLVM libFuzzer runtime.

For Windows Clang, use a Clang distribution that includes the libFuzzer runtime, a **Release** configuration, and `TESSERA_STATIC_RUNTIME=ON` (`/MT`). LLVM documents that Windows libFuzzer does not support `/MD` or incremental linking; the CMake option enforces `/MT` and disables incremental linking for fuzz executables.
