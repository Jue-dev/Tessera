param(
    [string]$BuildDirectory = "artifacts/x64/FuzzSmoke/build",
    [int]$Runs = 100
)

$ErrorActionPreference = "Stop"
if ($Runs -lt 1) {
    throw "Runs must be greater than zero."
}

$root = Split-Path -Parent $PSScriptRoot
$buildRoot = if ([System.IO.Path]::IsPathRooted($BuildDirectory)) {
    $BuildDirectory
} else {
    Join-Path $root $BuildDirectory
}

$targets = @(
    @{ Name = "tessera_fuzz_pattern"; Corpus = "pattern" },
    @{ Name = "tessera_fuzz_pe"; Corpus = "pe" },
    @{ Name = "tessera_fuzz_json"; Corpus = "json" },
    @{ Name = "tessera_fuzz_profile_json"; Corpus = "profile_json" },
    @{ Name = "tessera_fuzz_python_bridge"; Corpus = "python_bridge" },
    @{ Name = "tessera_fuzz_scanner"; Corpus = "scanner" },
    @{ Name = "tessera_fuzz_rtti_discovery"; Corpus = "rtti_discovery" },
    @{ Name = "tessera_fuzz_native_hook"; Corpus = "native_hook" }
)

foreach ($entry in $targets) {
    $executable = Join-Path $buildRoot "verify/fuzz/$($entry.Name).exe"
    $corpus = Join-Path $root "verify/fuzz/corpus/$($entry.Corpus)"
    if (-not (Test-Path $executable)) {
        if ($entry.Name -eq "tessera_fuzz_native_hook") { continue }
        throw "Missing fuzz executable: $executable"
    }
    if (-not (Test-Path $corpus)) { throw "Missing seed corpus: $corpus" }
    Write-Host "Replaying $($entry.Name) against $corpus ($Runs runs)"
    & $executable $corpus "-runs=$Runs"
    if ($LASTEXITCODE -ne 0) { throw "Fuzz replay failed ($LASTEXITCODE): $($entry.Name)" }
}
