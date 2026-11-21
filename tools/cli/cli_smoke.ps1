param(
 [Parameter(Mandatory=$true)][string]$CliPath,
 [Parameter(Mandatory=$true)][string]$FixturePath,
 [Parameter(Mandatory=$true)][string]$ProfilePath
)
$ErrorActionPreference = "Stop"
$WorkingProfile = Join-Path $env:TEMP ("tessera-cli-profile-" + [guid]::NewGuid().ToString("N") + ".json")
function Invoke-CliJson([string[]]$Arguments) {
    $output = & $CliPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("CLI failed (" + $LASTEXITCODE + "): " + ($Arguments -join " ") + [Environment]::NewLine + ($output -join [Environment]::NewLine))
    }
    $joined = $output -join [Environment]::NewLine
    try { return ($joined | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw ("Invalid JSON from CLI: " + $joined) }
}
try {
    $i = Invoke-CliJson @("inspect", $FixturePath, "--json")
    if ($i.architecture -ne "x64" -or $i.sections.Count -eq 0) { throw "inspect JSON did not include PE metadata" }
    $p = Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json
    $p.builds[0].fingerprint.sizeOfImage = "{0:X8}" -f [uint32]$i.sizeOfImage
    $p.builds[0].fingerprint.timestamp = "{0:X8}" -f [uint32]$i.timestamp
    $p.builds[0].fingerprint.checksum = "{0:X8}" -f [uint32]$i.checksum
    $p.builds[0].modules[0].sizeOfImage = "{0:X8}" -f [uint32]$i.sizeOfImage
    $p.builds[0].modules[0].timestamp = "{0:X8}" -f [uint32]$i.timestamp
    $p.builds[0].modules[0].checksum = "{0:X8}" -f [uint32]$i.checksum
    $p | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $WorkingProfile -Encoding utf8

    $s = Invoke-CliJson @("scan", $FixturePath, "--pattern", "90", "--section", ".text", "--json")
    if ($s.count -lt 0) { throw "scan returned invalid count" }
    $r = Invoke-CliJson @("rtti", $FixturePath, "--json")
    if ($null -eq $r.classes) { throw "rtti JSON did not include classes" }
    $v = Invoke-CliJson @("profile", "verify", $WorkingProfile, $FixturePath, "--json")
    if ($v.resolved -ne 1 -or $v.broken -ne 0) { throw "profile verify did not resolve the fixture entry" }
    $d = Invoke-CliJson @("profile", "diff", $WorkingProfile, $FixturePath, $FixturePath, "--json")
    if ($d.broken -ne 0 -or $d.moved -ne 0) { throw "profile diff failed on identical inputs" }
    $e = Invoke-CliJson @("export-symbols", $FixturePath, "--format", "json", "--profile", $WorkingProfile)
    if ($null -eq $e.exports -or $null -eq $e.rtti -or $null -eq $e.profile) { throw "export-symbols JSON incomplete" }
    Write-Host "Tessera CLI smoke passed."
} finally {
    if (Test-Path -LiteralPath $WorkingProfile) {
        Remove-Item -LiteralPath $WorkingProfile -Force
    }
}
