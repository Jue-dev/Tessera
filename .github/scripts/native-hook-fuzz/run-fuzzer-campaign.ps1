[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "x86")]
    [string]$Arch
)

$ErrorActionPreference = "Stop"
$RepoRoot = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
}

Push-Location $RepoRoot
try {
    if ($env:CAMPAIGN_SECONDS -notin @("300", "600", "900")) {
        throw "Unsupported fuzz duration: $env:CAMPAIGN_SECONDS"
    }

    $seedSource = Join-Path $RepoRoot "verify/fuzz/corpus/native_hook"
    $artifactRoot = Join-Path $RepoRoot "artifacts/native-hook-fuzz/$Arch"
    $corpus = Join-Path $artifactRoot "corpus"
    $crashes = Join-Path $artifactRoot "crashes"
    New-Item -ItemType Directory -Path $corpus -Force | Out-Null
    New-Item -ItemType Directory -Path $crashes -Force | Out-Null

    $seedFiles = @(Get-ChildItem -Path $seedSource -File)
    if ($seedFiles.Count -eq 0) {
        throw "The $Arch native-hook seed corpus is empty."
    }
    Copy-Item -Path (Join-Path $seedSource "*") -Destination $corpus -Recurse -Force

    $target = Join-Path $RepoRoot "build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
    if (-not (Test-Path -LiteralPath $target)) {
        throw "Missing $Arch native-hook fuzzer: $target"
    }

    if ($Arch -eq "x64") {
        $resource = (clang-cl -print-resource-dir).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $resource) {
            throw "Unable to locate Clang resource directory."
        }
        $asanDll = Join-Path $resource "lib/windows/clang_rt.asan_dynamic-x86_64.dll"
        if (-not (Test-Path -LiteralPath $asanDll)) {
            throw "Missing x64 ASan runtime DLL: $asanDll"
        }
        Copy-Item -LiteralPath $asanDll -Destination (Split-Path $target -Parent) -Force
    }
    else {
        $stagedAsan = Join-Path (Split-Path $target -Parent) "clang_rt.asan_dynamic-i386.dll"
        if (-not (Test-Path -LiteralPath $stagedAsan)) {
            throw "Missing staged x86 MSVC AddressSanitizer runtime: $stagedAsan"
        }
    }

    $campaignLogPath = Join-Path $artifactRoot "campaign.log"
    $rssLimit = if ($Arch -eq "x64") { 4096 } else { 1024 }
    $arguments = @(
        $corpus,
        "-max_total_time=$env:CAMPAIGN_SECONDS",
        "-timeout=10",
        "-max_len=96",
        "-rss_limit_mb=$rssLimit",
        "-seed=20261119",
        "-print_final_stats=1",
        "-artifact_prefix=$crashes/"
    )

    & $target @arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $campaignLogPath
    $fuzzerExitCode = $LASTEXITCODE
    if ($fuzzerExitCode -ne 0) {
        throw "$Arch coverage-guided fuzzing failed ($fuzzerExitCode)"
    }

    $campaignText = Get-Content -LiteralPath $campaignLogPath -Raw
    if ($campaignText -notmatch "stat::number_of_executed_units:\s*[1-9][0-9]*") {
        throw "$Arch fuzzer did not report any executed input units; refusing a false-positive pass."
    }

    $summary = [regex]::Match(
        $campaignText,
        "(?m)^Done\s+([0-9,]+)\s+runs\s+in\s+([0-9]+)\s+second"
    )
    if (-not $summary.Success) {
        throw "$Arch fuzzer did not report a completed run count and elapsed time."
    }

    $executedRuns = [UInt64](($summary.Groups[1].Value -replace ",", ""))
    $elapsedSeconds = [UInt32]$summary.Groups[2].Value
    $minimumDuration = [Math]::Max(1, [Int32]$env:CAMPAIGN_SECONDS - 5)
    if ($executedRuns -lt 100000 -or $elapsedSeconds -lt $minimumDuration) {
        throw "$Arch fuzz campaign under-ran: runs=$executedRuns, seconds=$elapsedSeconds."
    }

    if ($Arch -eq "x86") {
        # MSVC Fuzzer reports discovered coverage features as ft:, not LLVM cov:.
        $featureSummary = [regex]::Match($campaignText, "DONE\s+ft:\s*([1-9][0-9]*)")
        if (-not $featureSummary.Success) {
            throw "x86 MSVC Fuzzer did not report non-zero coverage features in its final DONE summary."
        }
        $coverageFeatures = [UInt64]$featureSummary.Groups[1].Value
        Write-Host "x86 MSVC Fuzzer summary: $executedRuns executions in $elapsedSeconds seconds; $coverageFeatures coverage features."
    }
    else {
        Write-Host "x64 libFuzzer campaign completed $executedRuns runs in $elapsedSeconds seconds."
    }

    Get-Content -LiteralPath $campaignLogPath -Tail 40 | ForEach-Object { Write-Host $_ }
    Write-Host "Full $Arch campaign log: $campaignLogPath"
}
finally {
    Pop-Location
}
