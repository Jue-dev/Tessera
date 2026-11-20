cmake --build build-native-hook-fuzz --target tessera_fuzz_native_hook --parallel
if ($LASTEXITCODE -ne 0) { throw "x64 native-hook fuzzer build failed ($LASTEXITCODE)" }
