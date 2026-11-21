param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64-bench", "x64-fuzz-smoke")]
    [string]$Preset
)
$ErrorActionPreference = "Stop"
cmake --preset $Preset
if ($LASTEXITCODE -ne 0) { throw "Configure failed for $Preset ($LASTEXITCODE)." }
cmake --build --preset $Preset --parallel
if ($LASTEXITCODE -ne 0) { throw "Build failed for $Preset ($LASTEXITCODE)." }
ctest --preset $Preset --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "CTest failed for $Preset ($LASTEXITCODE)." }

if ($Preset -eq "x64-bench") {
    cmake --preset x64-bench-scalar
    if ($LASTEXITCODE -ne 0) { throw "Scalar benchmark configure failed ($LASTEXITCODE)." }
    cmake --build artifacts/x64/Bench/Scalar/build --config Release --target tessera_bench --parallel
    if ($LASTEXITCODE -ne 0) { throw "Scalar benchmark build failed ($LASTEXITCODE)." }

    $simdExe = ".\artifacts\x64\Bench\build\verify\bench\tessera_bench.exe"
    $scalarExe = ".\artifacts\x64\Bench\Scalar\build\verify\bench\tessera_bench.exe"
    foreach ($exe in @($simdExe, $scalarExe)) {
        if (-not (Test-Path $exe)) { throw "Missing benchmark executable: $exe" }
    }
    $simdJson = & $simdExe --json | Out-String
    if ($LASTEXITCODE -ne 0) { throw "SIMD benchmark failed ($LASTEXITCODE)." }
    $scalarJson = & $scalarExe --json | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Scalar benchmark failed ($LASTEXITCODE)." }
    $simd = $simdJson | ConvertFrom-Json -ErrorAction Stop
    $scalar = $scalarJson | ConvertFrom-Json -ErrorAction Stop
    if (-not $simd.benchmarks -or -not $scalar.benchmarks) {
        throw "Benchmark JSON must contain non-empty benchmark arrays."
    }
    $patternNames = @(
        "pattern_masked_4mib",
        "pattern_exact_literal_4mib",
        "pattern_high_frequency_prolog_4mib",
        "pattern_leading_wildcard_4mib",
        "pattern_dense_nibble_4mib"
    )
    $summary = @(
        "### x64 Pattern Throughput: SIMD Dispatch vs Scalar", "",
        "| Workload | Scalar (MB/s) | SIMD dispatch (MB/s) | Speedup |",
        "|---|---:|---:|---:|"
    )
    foreach ($name in $patternNames) {
        $scalarMetric = @($scalar.benchmarks | Where-Object { $_.name -eq $name })
        $simdMetric = @($simd.benchmarks | Where-Object { $_.name -eq $name })
        if ($scalarMetric.Count -ne 1 -or $simdMetric.Count -ne 1) {
            throw "Missing or duplicate benchmark metric: $name"
        }
        $scalarRate = [double]$scalarMetric[0].mb_per_s
        $simdRate = [double]$simdMetric[0].mb_per_s
        if ($scalarRate -le 0 -or $simdRate -le 0) { throw "Invalid throughput for $name." }
        $speedup = $simdRate / $scalarRate
        $delta = ($speedup - 1.0) * 100.0
        $summary += "| $name | $([math]::Round($scalarRate, 2)) | $([math]::Round($simdRate, 2)) | $([math]::Round($speedup, 3))x ($([math]::Round($delta, 1))%) |"
        Write-Host ("{0}: scalar={1:N2} MB/s; SIMD={2:N2} MB/s; speedup={3:N3}x ({4:N1}%)" -f $name, $scalarRate, $simdRate, $speedup, $delta)
    }
    $summary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}
