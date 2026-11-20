$ErrorActionPreference = "Stop"
$seedSource = Join-Path $env:GITHUB_WORKSPACE "verify/fuzz/corpus/native_hook"
$artifactRoot = Join-Path $env:GITHUB_WORKSPACE "artifacts/native-hook-fuzz/x86"
$corpus = Join-Path $artifactRoot "corpus"
$crashes = Join-Path $artifactRoot "crashes"
New-Item -ItemType Directory -Path $corpus -Force | Out-Null
New-Item -ItemType Directory -Path $crashes -Force | Out-Null
$seedFiles = @(Get-ChildItem -Path $seedSource -File)
if ($seedFiles.Count -eq 0) { throw "The x86 native-hook seed corpus is empty." }
Copy-Item -Path (Join-Path $seedSource "*") -Destination $corpus -Recurse -Force

if ($env:CAMPAIGN_SECONDS -notin @("300", "600", "900")) {
  throw "Unsupported fuzz duration: $env:CAMPAIGN_SECONDS"
}
$target = Join-Path $env:GITHUB_WORKSPACE "build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
if (-not (Test-Path $target)) { throw "Missing x86 native-hook fuzzer: $target" }

$campaignLog = Join-Path $artifactRoot "campaign.log"
$arguments = @(
  $corpus,
  "-max_total_time=$env:CAMPAIGN_SECONDS",
  "-timeout=10",
  "-max_len=96",
  "-rss_limit_mb=1024",
  "-seed=20261119",
  "-print_final_stats=1",
  "-artifact_prefix=$crashes/"
)

# Stream campaign progress live and save the same output for artifacts.
& $target @arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $campaignLog
$fuzzerExitCode = $LASTEXITCODE
if ($fuzzerExitCode -ne 0) { throw "x86 coverage-guided Fuzzer/ASan campaign failed ($fuzzerExitCode)" }
$campaignText = Get-Content $campaignLog -Raw

$summary = [regex]::Match($campaignText, "(?m)^Done\s+([0-9,]+)\s+runs\s+in\s+([0-9]+)\s+second")
if (-not $summary.Success) {
  throw "x86 MSVC Fuzzer did not report its completed run count and elapsed time."
}
$executedRuns = [UInt64](($summary.Groups[1].Value -replace ",", ""))
$elapsedSeconds = [UInt32]$summary.Groups[2].Value
$minimumDuration = [Math]::Max(1, [Int32]$env:CAMPAIGN_SECONDS - 5)
if ($executedRuns -lt 100000 -or $elapsedSeconds -lt $minimumDuration) {
  throw "x86 fuzz campaign was too short or processed too few inputs: runs=$executedRuns, seconds=$elapsedSeconds."
}
if ($campaignText -notmatch "stat::number_of_executed_units:\s*[1-9][0-9]*") {
  throw "x86 MSVC Fuzzer did not report executed input units."
}
# MSVC's Fuzzer reports discovered coverage features as "ft:", not
# libFuzzer's LLVM-specific "cov:" field. Validate the final DONE line.
$featureSummary = [regex]::Match($campaignText, "DONE\s+ft:\s*([1-9][0-9]*)")
if (-not $featureSummary.Success) {
  throw "x86 MSVC Fuzzer did not report non-zero coverage features in its final DONE summary."
}
$coverageFeatures = [UInt64]$featureSummary.Groups[1].Value

Write-Host "x86 MSVC Fuzzer summary: $executedRuns executions in $elapsedSeconds seconds; $coverageFeatures coverage features."
Get-Content $campaignLog -Tail 40 | ForEach-Object { Write-Host $_ }
Write-Host "Full x86 campaign log: $campaignLog"
