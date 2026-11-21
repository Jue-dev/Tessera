param(
    [string]$BuildDirectory = "build-nortti",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$fuzzTargets = @(
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_pattern.exe"; Corpus = "verify/fuzz/corpus/pattern" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_pe.exe"; Corpus = "verify/fuzz/corpus/pe" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_json.exe"; Corpus = "verify/fuzz/corpus/json" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_profile_json.exe"; Corpus = "verify/fuzz/corpus/profile_json" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_python_bridge.exe"; Corpus = "verify/fuzz/corpus/python_bridge" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_scanner.exe"; Corpus = "verify/fuzz/corpus/scanner" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_rtti_discovery.exe"; Corpus = "verify/fuzz/corpus/rtti_discovery" },
    @{ Path = "$BuildDirectory/verify/fuzz/$Configuration/tessera_fuzz_native_hook.exe"; Corpus = "verify/fuzz/corpus/native_hook" }
)
foreach ($entry in $fuzzTargets) {
    $target = $entry.Path
    $corpus = $entry.Corpus
    if (-not (Test-Path $target)) {
        throw "Missing Release fuzz smoke target: $target"
    }
    if (-not (Test-Path $corpus)) {
        throw "Missing fuzz seed corpus: $corpus"
    }
    Write-Host "Running $target with seed corpus $corpus"
    & $target $corpus "-runs=100"
    if ($LASTEXITCODE -ne 0) {
        throw "Fuzz smoke failed ($LASTEXITCODE): $target"
    }
}

$benchmarkTargets = @(
    "$BuildDirectory/verify/bench/$Configuration/tessera_bench.exe",
    "$BuildDirectory/verify/bench/$Configuration/tessera_decoder_bench.exe",
    "$BuildDirectory/verify/bench/$Configuration/tessera_pe_bench.exe",
    "$BuildDirectory/verify/bench/$Configuration/tessera_json_bench.exe",
    "$BuildDirectory/verify/bench/$Configuration/tessera_rtti_discovery_bench.exe"
)
foreach ($target in $benchmarkTargets) {
    if (-not (Test-Path $target)) {
        throw "Missing Release benchmark target: $target"
    }
    Write-Host "Running $target"
    & $target
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark smoke failed ($LASTEXITCODE): $target"
    }
}
