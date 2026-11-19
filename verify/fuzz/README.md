# Tessera fuzz targets

The harnesses expose `LLVMFuzzerTestOneInput` for JSON parsing/writing, byte-pattern parsing/search, PE parsing, and (on Windows) native inline-hook instruction decoding/relocation.

## Standalone smoke mode (default)

With `TESSERA_BUILD_FUZZ=ON` and `TESSERA_ENABLE_LIBFUZZER=OFF`, the targets keep a small `main()` so they can run without the LLVM libFuzzer runtime. The native-hook executable does more than a single link/run check: it submits focused branch/terminal/VEX/EVEX seeds and 512 fixed-seed random byte sequences through the real attach/detach path.

The Windows-only `tessera_fuzz_native_hook` target feeds up to 96 arbitrary bytes into an isolated executable page. It never executes the supplied instruction bytes or the generated trampoline. Rejected inputs are checked for failure-atomicity; accepted inputs must detach and restore all original bytes. The standalone corpus is deterministic (seed `0xC0FFEE42`) so a CI failure can be reproduced exactly. The known-good seed must complete at least one attach/detach lifecycle or the executable fails.

Standalone smoke mode is still not a substitute for a sustained coverage-guided fuzzing campaign.

## Native-hook seed corpus and scheduled campaign

The binary seed corpus for the native hook harness lives in
`verify/fuzz/corpus/native_hook`. It includes a known-good leaf prologue and
focused relative-branch, terminal-padding, VEX, and EVEX encodings. The corpus
is copied to the runner workspace before fuzzing so libFuzzer can minimize and
add discoveries without modifying the checked-out source tree.

The `Native Hook Coverage-Guided Fuzz` workflow runs a bounded five-minute
Windows x64 Clang libFuzzer campaign weekly and can also be started manually.
It instruments the production Tessera modules with AddressSanitizer and
UndefinedBehaviorSanitizer, runs the native hook harness with a 96-byte input
limit, and uploads the evolving corpus and crash artifacts. This campaign
complements, but does not replace, the x86/x64 Debug/Release PR smoke matrix
or real application integration tests.

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
