param(
 [Parameter(Mandatory=$true)][ValidateSet("fuzz-bench","decoder-oracle","examples")][string]$Task,
 [string]$BuildDirectory="build-nortti",[string]$Configuration="Release"
)
$ErrorActionPreference="Stop"
switch($Task){
 "decoder-oracle" {
  cmake -S . -B build-decoder-oracle -G Ninja -DCMAKE_BUILD_TYPE=Release -DTESSERA_BUILD_TESTS=ON -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_ENABLE_DECODER_ORACLE=ON
  if($LASTEXITCODE -ne 0){throw "Decoder oracle configure failed."}
  cmake --build build-decoder-oracle --target tessera_decoder_probe --parallel
  if($LASTEXITCODE -ne 0){throw "Decoder probe build failed."}
  ctest --test-dir build-decoder-oracle -R tessera_decoder_differential --output-on-failure
  if($LASTEXITCODE -ne 0){throw "Decoder differential failed."}
 }
 "examples" {
  $items=@("artifacts/x64/Release/build/examples/tessera_example_01_scan_and_pe.exe","artifacts/x64/Release/build/examples/tessera_example_03_rtti_and_reflection.exe","artifacts/x64/Release/build/examples/tessera_example_04_blind_discovery.exe","artifacts/x64/Release/build/examples/tessera_example_05_python_bridge.exe","artifacts/x64/Release/build/examples/tessera_example_06_profiles_and_targets.exe")
  foreach($f in $items){if(!(Test-Path $f)){throw "Missing example $f"};& $f;if($LASTEXITCODE -ne 0){throw "Example failed: $f"}}
 }
 "fuzz-bench" {
  $fuzz=@(
   @("pattern","tessera_fuzz_pattern"),@("pe","tessera_fuzz_pe"),@("json","tessera_fuzz_json"),@("profile_json","tessera_fuzz_profile_json"),
   @("python_bridge","tessera_fuzz_python_bridge"),@("scanner","tessera_fuzz_scanner"),@("rtti_discovery","tessera_fuzz_rtti_discovery"),@("native_hook","tessera_fuzz_native_hook"))
  foreach($e in $fuzz){$exe="$BuildDirectory/verify/fuzz/$Configuration/$($e[1]).exe";$corpus="verify/fuzz/corpus/$($e[0])";if(!(Test-Path $exe)-or !(Test-Path $corpus)){throw "Missing fuzz target/corpus: $($e[1])"};& $exe $corpus "-runs=100";if($LASTEXITCODE -ne 0){throw "Fuzz corpus replay failed: $($e[1])"}}
  $bench=@("tessera_bench","tessera_decoder_bench","tessera_pe_bench","tessera_json_bench","tessera_rtti_discovery_bench")|ForEach-Object{"$BuildDirectory/verify/bench/$Configuration/$_.exe"}
  foreach($exe in $bench){if(!(Test-Path $exe)){throw "Missing benchmark $exe"};& $exe;if($LASTEXITCODE -ne 0){throw "Benchmark smoke failed: $exe"};$json=& $exe --json | Out-String;if($LASTEXITCODE -ne 0){throw "Benchmark JSON failed: $exe"};$o=$json|ConvertFrom-Json -ErrorAction Stop;if(!$o){throw "Empty benchmark JSON: $exe"}}
  $root=(Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
  & python (Join-Path $root "verify/bench/validate_bench_json.py") @bench
  if($LASTEXITCODE -ne 0){throw "Benchmark JSON validator failed."}
 }
}