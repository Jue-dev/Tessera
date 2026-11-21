param(
 [Parameter(Mandatory=$true)][string]$CliPath,
 [Parameter(Mandatory=$true)][string]$FixturePath,
 [Parameter(Mandatory=$true)][string]$ProfilePath
)
$ErrorActionPreference = "Stop"
function Invoke-CliJson([string[]]$Arguments) {
    $output = & $CliPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("CLI failed (" + $LASTEXITCODE + "): " + ($Arguments -join " ") + [Environment]::NewLine + ($output -join [Environment]::NewLine))
    }
    $joined = $output -join [Environment]::NewLine
    try { return ($joined | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw ("Invalid JSON from CLI: " + $joined) }
}
$i = Invoke-CliJson @("inspect", $FixturePath, "--json")
if ($i.architecture -ne "x64" -or $i.sections.Count -eq 0) { throw "inspect JSON did not include PE metadata" }
# Match the profile's PE identity to the generated fixture.
$p = Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json
$size = "{0:X8}" -f [uint32]$i.sizeOfImage
$timestamp = "{0:X8}" -f [uint32]$i.timestamp
$checksum = "{0:X8}" -f [uint32]$i.checksum
foreach ($record in @($p.builds[0].fingerprint, $p.builds[0].modules[0])) {
    $record.sizeOfImage = $size
    $record.timestamp = $timestamp
    $record.checksum = $checksum
}
$p | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $ProfilePath -Encoding utf8
$s = Invoke-CliJson @("scan", $FixturePath, "--pattern", "90", "--section", ".text", "--json")
if ($s.count -lt 0) { throw "scan returned invalid count" }
$r = Invoke-CliJson @("rtti", $FixturePath, "--json")
if ($null -eq $r.classes) { throw "rtti JSON did not include classes" }
$v = Invoke-CliJson @("profile", "verify", $ProfilePath, $FixturePath, "--json")
if ($v.resolved -ne 1 -or $v.broken -ne 0) { throw "profile verify did not resolve the fixture entry" }
$d = Invoke-CliJson @("profile", "diff", $ProfilePath, $FixturePath, $FixturePath, "--json")
if ($d.broken -ne 0 -or $d.moved -ne 0) { throw "profile diff failed on identical inputs" }
$e = Invoke-CliJson @("export-symbols", $FixturePath, "--format", "json", "--profile", $ProfilePath)
if ($null -eq $e.exports -or $null -eq $e.rtti -or $null -eq $e.profile) { throw "export-symbols JSON incomplete" }
Write-Host "Tessera CLI smoke passed."
