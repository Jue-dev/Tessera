param(
    [Parameter(Mandatory = $true)]
    [string]$DetoursRoot,
    [ValidateSet("x64", "x86")]
    [string]$Architecture = "x64",
    [ValidateSet("Release")]
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
& .\verify\windows\run_detours_integration.ps1 -DetoursRoot $DetoursRoot -Architecture $Architecture -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Detours integration validation failed ($LASTEXITCODE)."
}
