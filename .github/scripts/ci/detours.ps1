param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Build", "Verify")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [ValidateSet("x86", "x64")]
    [string]$Architecture
)

$ErrorActionPreference = "Stop"
$detoursArch = if ($Architecture -eq "x86") { "X86" } else { "X64" }

if ($Action -eq "Build") {
    nmake /nologo "DETOURS_TARGET_PROCESSOR=$detoursArch"
    if ($LASTEXITCODE -ne 0) {
        throw "Detours NMake failed ($LASTEXITCODE)."
    }
    return
}

$workspace = if ($env:GITHUB_WORKSPACE) { $env:GITHUB_WORKSPACE } else { (Get-Location).Path }
$library = Join-Path $workspace "dependencies/Detours/lib.$detoursArch/detours.lib"
$header = Join-Path $workspace "dependencies/Detours/include/detours.h"
if (-not (Test-Path $library)) {
    throw "Missing architecture-specific library: $library"
}
if (-not (Test-Path $header)) {
    throw "Missing Detours header: $header"
}
Write-Host "Detours header: $header"
Write-Host "Detours library: $library"
