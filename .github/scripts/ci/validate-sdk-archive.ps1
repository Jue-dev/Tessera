param(
    [string]$ArchivePath = ".\Tessera-SDK-Windows.zip",
    [string]$ChecksumPath = ".\SHA256SUMS.txt"
)
$ErrorActionPreference = "Stop"
$archivePathResolved = (Resolve-Path -LiteralPath $ArchivePath).Path
$checksumLine = (Get-Content -LiteralPath $ChecksumPath -Raw).Trim()
$archiveName = [IO.Path]::GetFileName($ArchivePath)
if ($checksumLine -notmatch ('^(?<hash>[0-9a-fA-F]{64})  ' + [regex]::Escape($archiveName) + '$')) {
    throw "SHA256SUMS.txt has an invalid format."
}
$declaredHash = $Matches.hash.ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $archivePathResolved -Algorithm SHA256).Hash.ToLowerInvariant()
if ($declaredHash -ne $actualHash) { throw "SDK archive checksum mismatch." }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePathResolved)
try {
    $entries = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
    $requiredEntries = @(
        "include/tessera/tessera.hpp",
        "x64/Release/lib/tessera.lib",
        "x64/Debug/lib/tessera.lib",
        "x86/Release/lib/tessera.lib",
        "x86/Debug/lib/tessera.lib",
        "x64/Release/lib/cmake/Tessera/TesseraConfig.cmake",
        "x64/Debug/lib/cmake/Tessera/TesseraConfig.cmake",
        "x86/Release/lib/cmake/Tessera/TesseraConfig.cmake",
        "x86/Debug/lib/cmake/Tessera/TesseraConfig.cmake"
    )
    $missing = @($requiredEntries | Where-Object { $_ -notin $entries })
    if ($missing.Count -gt 0) { throw "SDK archive is missing entries: $($missing -join ', ')" }
} finally {
    $archive.Dispose()
}
Write-Host "Validated SDK archive and SHA256SUMS.txt."
