param(
    [string]$ArchivePath = ".\Tessera-SDK-Windows.zip",
    [string]$ChecksumPath = ".\SHA256SUMS.txt"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ArchivePath)) { throw "Missing SDK archive: $ArchivePath" }
$archive = Get-Item -LiteralPath $ArchivePath
if ($archive.Length -le 0) { throw "SDK archive is empty: $ArchivePath" }
$hash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($ArchivePath))" | Out-File -LiteralPath $ChecksumPath -Encoding ascii
