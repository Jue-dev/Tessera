$ErrorActionPreference = "Stop"
$seedSource = Join-Path $env:GITHUB_WORKSPACE "verify/fuzz/corpus/native_hook"
$artifactRoot = Join-Path $env:GITHUB_WORKSPACE "artifacts/native-hook-fuzz/x64"
$corpus = Join-Path $artifactRoot "corpus"
$crashes = Join-Path $artifactRoot "crashes"
New-Item -ItemType Directory -Path $corpus -Force | Out-Null
New-Item -ItemType Directory -Path $crashes -Force | Out-Null
$seedFiles = @(Get-ChildItem -Path $seedSource -File)
if ($seedFiles.Count -eq 0) { throw "The x64 native-hook seed corpus is empty." }
Copy-Item -Path (Join-Path $seedSource "*") -Destination $corpus -Recurse -Force

if ($env:CAMPAIGN_SECONDS -notin @("300", "600", "900")) {
  throw "Unsupported fuzz duration: $env:CAMPAIGN_SECONDS"
}
$target = Join-Path $env:GITHUB_WORKSPACE "build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
if (-not (Test-Path $target)) { throw "Missing x64 native-hook fuzzer: $target" }

$resource = (clang-cl -print-resource-dir).Trim()
if ($LASTEXITCODE -ne 0 -or -not $resource) { throw "Unable to locate Clang resource directory." }
$asanDll = Join-Path $resource "lib/windows/clang_rt.asan_dynamic-x86_64.dll"
if (-not (Test-Path $asanDll)) { throw "Missing x64 ASan runtime DLL: $asanDll" }
Copy-Item $asanDll (Split-Path $target -Parent) -Force

$campaignLogPath = Join-Path $artifactRoot "campaign.log"
$arguments = @(
  $corpus,
  "-max_total_time=$env:CAMPAIGN_SECONDS",
  "-timeout=10",
  "-max_len=96",
  "-rss_limit_mb=4096",
  "-seed=20261119",
  "-print_final_stats=1",
  "-artifact_prefix=$crashes/"
)

# Stream fuzzer progress into the Actions log while preserving a full
# campaign log artifact. Avoid Start-Process -Wait, which hides progress
# and makes a healthy timed campaign look hung.
& $target @arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $campaignLogPath
$fuzzerExitCode = $LASTEXITCODE
if ($fuzzerExitCode -ne 0) { throw "x64 coverage-guided fuzzing failed ($fuzzerExitCode)" }
$campaignLog = Get-Content $campaignLogPath -Raw
if ($campaignLog -notmatch "stat::number_of_executed_units:\s*[1-9][0-9]*") {
  throw "libFuzzer did not report any executed input units; refusing a false-positive pass."
}
$summary = [regex]::Match($campaignLog, "(?m)^Done\s+([0-9,]+)\s+runs\s+in\s+([0-9]+)\s+second")
if (-not $summary.Success) { throw "x64 libFuzzer campaign summary is missing." }
$runs = [UInt64](($summary.Groups[1].Value -replace ",", ""))
$seconds = [UInt32]$summary.Groups[2].Value
$minimumSeconds = [Math]::Max(1, [Int32]$env:CAMPAIGN_SECONDS - 5)
if ($runs -lt 100000 -or $seconds -lt $minimumSeconds) {
  throw "x64 campaign under-ran: runs=$runs, seconds=$seconds."
}
Write-Host "x64 campaign completed $runs runs in $seconds seconds."
