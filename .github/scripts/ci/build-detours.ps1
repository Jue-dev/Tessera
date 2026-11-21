param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86", "x64")]
    [string]$Architecture
)

$ErrorActionPreference = "Stop"
$targetProcessor = if ($Architecture -eq "x86") { "X86" } else { "X64" }
nmake /nologo "DETOURS_TARGET_PROCESSOR=$targetProcessor"
if ($LASTEXITCODE -ne 0) {
    throw "Detours NMake failed ($LASTEXITCODE)."
}
