$ErrorActionPreference = "Stop"
if ($env:VSCMD_ARG_TGT_ARCH -ne "x86") {
  throw "Expected x86 MSVC target environment, got '$env:VSCMD_ARG_TGT_ARCH'."
}

$probeSource = Join-Path $env:RUNNER_TEMP "tessera_msvc_x86_fuzzer_probe.cpp"
$probeExe = Join-Path $env:RUNNER_TEMP "tessera_msvc_x86_fuzzer_probe.exe"
@'
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    volatile std::uint8_t value = size == 0 ? 0 : data[0];
    (void)value;
    return 0;
}
'@ | Set-Content -Path $probeSource -Encoding ascii

cl /nologo /std:c++latest /Zc:__cplusplus /EHsc /MT /fsanitize=address /fsanitize=fuzzer $probeSource "/Fe:$probeExe"
if ($LASTEXITCODE -ne 0) { throw "MSVC x86 Fuzzer/ASan probe compile failed ($LASTEXITCODE)" }
if (-not (Test-Path $probeExe)) { throw "MSVC x86 Fuzzer probe executable was not produced." }

$probeOutput = & $probeExe "-runs=8" 2>&1
$probeExitCode = $LASTEXITCODE
$probeOutput | ForEach-Object { Write-Host $_ }
if ($probeExitCode -ne 0) { throw "MSVC x86 Fuzzer/ASan probe execution failed ($probeExitCode)" }
$probeText = [string]::Join([Environment]::NewLine, @($probeOutput))
if ($probeText -notmatch "Done\s+8\s+runs") {
  throw "MSVC x86 Fuzzer probe did not complete the requested eight executions."
}

$asanName = "clang_rt.asan_dynamic-i386.dll"
$searchRoots = @($env:VCToolsInstallDir, $env:VCToolsRedistDir) | Where-Object { $_ -and (Test-Path $_) }
$asanDll = $null
foreach ($root in $searchRoots) {
  $match = Get-ChildItem -Path $root -Filter $asanName -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($match) { $asanDll = $match.FullName; break }
}
if (-not $asanDll) { throw "MSVC x86 AddressSanitizer runtime DLL '$asanName' was not found." }
Write-Host "Verified MSVC x86 Fuzzer and ASan runtime: $asanDll"
