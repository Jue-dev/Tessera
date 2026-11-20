$ErrorActionPreference = "Stop"
$asanName = "clang_rt.asan_dynamic-i386.dll"
$searchRoots = @($env:VCToolsInstallDir, $env:VCToolsRedistDir) | Where-Object { $_ -and (Test-Path $_) }
$asanDll = $null
foreach ($root in $searchRoots) {
  $match = Get-ChildItem -Path $root -Filter $asanName -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($match) { $asanDll = $match.FullName; break }
}
if (-not $asanDll) { throw "MSVC x86 AddressSanitizer runtime DLL '$asanName' was not found." }
$targetDir = Join-Path $env:GITHUB_WORKSPACE "build-native-hook-fuzz/verify/fuzz"
Copy-Item $asanDll (Join-Path $targetDir $asanName) -Force
Write-Host "Staged x86 ASan runtime: $asanDll"
