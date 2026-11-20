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
    if ($Arch -eq "x64") {
        $clang = Get-Command clang-cl -ErrorAction Stop
        Write-Host "Using clang-cl: $($clang.Source)"
        & $clang.Source --version
        if ($LASTEXITCODE -ne 0) { throw "clang-cl version check failed ($LASTEXITCODE)" }

        & $clang.Source "--target=x86_64-pc-windows-msvc" -v
        if ($LASTEXITCODE -ne 0) { throw "clang-cl x64 target check failed ($LASTEXITCODE)" }

        $resource = (& $clang.Source -print-resource-dir).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $resource) {
            throw "Unable to locate Clang resource directory."
        }

        $runtimeDir = Join-Path $resource "lib/windows"
        $required = @(
            "clang_rt.fuzzer-x86_64.lib",
            "clang_rt.asan_dynamic-x86_64.lib",
            "clang_rt.asan_static_runtime_thunk-x86_64.lib",
            "clang_rt.asan_dynamic-x86_64.dll"
        )
        foreach ($name in $required) {
            $path = Join-Path $runtimeDir $name
            if (-not (Test-Path -LiteralPath $path)) {
                throw "Missing required x64 Clang runtime: $path"
            }
            Write-Host "Found: $name"
        }
        return
    }

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
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC x86 Fuzzer/ASan probe compile failed ($LASTEXITCODE)"
    }
    if (-not (Test-Path -LiteralPath $probeExe)) {
        throw "MSVC x86 Fuzzer probe executable was not produced."
    }

    $probeOutput = & $probeExe "-runs=8" 2>&1
    $probeExitCode = $LASTEXITCODE
    $probeOutput | ForEach-Object { Write-Host $_ }
    if ($probeExitCode -ne 0) {
        throw "MSVC x86 Fuzzer/ASan probe execution failed ($probeExitCode)"
    }
    $probeText = [string]::Join([Environment]::NewLine, @($probeOutput))
    if ($probeText -notmatch "Done\s+8\s+runs") {
        throw "MSVC x86 Fuzzer probe did not complete the requested eight executions."
    }

    $asanName = "clang_rt.asan_dynamic-i386.dll"
    $searchRoots = @($env:VCToolsInstallDir, $env:VCToolsRedistDir) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $asanDll = $null
    foreach ($root in $searchRoots) {
        $match = Get-ChildItem -Path $root -Filter $asanName -File -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($match) {
            $asanDll = $match.FullName
            break
        }
    }
    if (-not $asanDll) {
        throw "MSVC x86 AddressSanitizer runtime DLL '$asanName' was not found."
    }

    $targetDir = Join-Path $RepoRoot "build-native-hook-fuzz/verify/fuzz"
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Copy-Item -LiteralPath $asanDll -Destination (Join-Path $targetDir $asanName) -Force
    Write-Host "Verified and staged MSVC x86 Fuzzer/ASan runtime: $asanDll"
}
finally {
    Pop-Location
}
