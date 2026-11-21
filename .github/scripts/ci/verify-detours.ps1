param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86", "x64")]
    [string]$Architecture
)

$ErrorActionPreference = "Stop"
$detoursArch = if ($Architecture -eq "x86") { "X86" } else { "X64" }
$library = Join-Path $env:GITHUB_WORKSPACE "dependencies/Detours/lib.$detoursArch/detours.lib"
$header = Join-Path $env:GITHUB_WORKSPACE "dependencies/Detours/include/detours.h"
if (-not (Test-Path $library)) {
    throw "Missing architecture-specific library: $library"
}
if (-not (Test-Path $header)) {
    throw "Missing Detours header: $header"
}
Write-Host "Detours header: $header"
Write-Host "Detours library: $library"
