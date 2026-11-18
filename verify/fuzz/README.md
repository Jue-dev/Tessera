# Tessera fuzz targets

The harnesses expose `LLVMFuzzerTestOneInput` for JSON parsing/writing, byte-pattern parsing/search, PE parsing, and (on Windows) native inline-hook instruction decoding/relocation.

## Standalone smoke mode (default)

With `TESSERA_BUILD_FUZZ=ON` and `TESSERA_ENABLE_LIBFUZZER=OFF`, each target keeps a small `main()` that feeds one representative input. This checks that the harness links and runs, but it is **not fuzzing**.

The Windows-only `tessera_fuzz_native_hook` target feeds up to 96 arbitrary bytes into an isolated executable page and exercises the real native backend's attach/detach path. It never executes the supplied instruction bytes or the generated trampoline. Rejected inputs are checked for failure-atomicity; accepted inputs must detach and restore all original bytes.

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
