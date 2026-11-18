<#
.SYNOPSIS
    Cleans unnecessary build, install, IDE cache, and temporary files from the Tessera workspace.
.PARAMETER DryRun
    Lists all directories and files that would be removed and calculates space savings without deleting anything.
.PARAMETER BuildOnly
    Removes only build/install/dist directories (artifacts/, build/, out/, dist/).
.PARAMETER IdeOnly
    Removes only IDE and language-server caches (.vs/, .cache/, compile_commands.json).
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$BuildOnly,
    [switch]$IdeOnly
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "=== Tessera Workspace Cleaner ===" -ForegroundColor Cyan
Write-Host "Workspace : $RepoRoot"
if ($DryRun) {
    Write-Host "Mode      : DRY-RUN (No files will be deleted)" -ForegroundColor Yellow
}

$BuildTargets = @(
    "artifacts",
    "build",
    "build-nortti",
    "install-nortti",
    "out",
    "dist",
    "vcpkg_installed",
    "CMakeFiles",
    "CMakeCache.txt",
    "cmake_install.cmake"
)

$IdeTargets = @(
    ".vs",
    ".cache",
    "compile_commands.json"
)

$TargetRelativePaths = @()
if ($BuildOnly) {
    $TargetRelativePaths += $BuildTargets
} elseif ($IdeOnly) {
    $TargetRelativePaths += $IdeTargets
} else {
    $TargetRelativePaths += $BuildTargets
    $TargetRelativePaths += $IdeTargets
}

$ItemsToRemove = New-Object System.Collections.Generic.List[System.IO.FileSystemInfo]

foreach ($rel in $TargetRelativePaths) {
    $full = Join-Path $RepoRoot $rel
    if (Test-Path -LiteralPath $full) {
        $ItemsToRemove.Add((Get-Item -LiteralPath $full -Force))
    }
}

# Also scan source directories for stray temporary artifacts (.obj, .pdb, .ilk, .exp, .log, .tmp, .bak, .tlog)
if (-not $BuildOnly -and -not $IdeOnly) {
    $StrayExtensions = @(".obj", ".pdb", ".ilk", ".exp", ".log", ".tmp", ".bak", ".tlog")
    $SafeDirs = @("include", "src", "verify", "examples", "cmake", "docs", "scripts")
    foreach ($dir in $SafeDirs) {
        $dirPath = Join-Path $RepoRoot $dir
        if (Test-Path -LiteralPath $dirPath) {
            $strayFiles = Get-ChildItem -LiteralPath $dirPath -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $StrayExtensions -contains $_.Extension.ToLowerInvariant() }
            foreach ($f in $strayFiles) {
                $ItemsToRemove.Add($f)
            }
        }
    }

    # Check system temp folder for leftover test directories
    $TempTesseraDirs = @(
        (Join-Path ([System.IO.Path]::GetTempPath()) "tessera_fs_test"),
        (Join-Path ([System.IO.Path]::GetTempPath()) "tessera_profile_test")
    )
    foreach ($td in $TempTesseraDirs) {
        if (Test-Path -LiteralPath $td) {
            $ItemsToRemove.Add((Get-Item -LiteralPath $td -Force))
        }
    }
}

if ($ItemsToRemove.Count -eq 0) {
    Write-Host "`nWorkspace is already completely clean!" -ForegroundColor Green
    exit 0
}

[int64]$TotalBytes = 0
Write-Host "`nFound $($ItemsToRemove.Count) item(s) to clean:" -ForegroundColor Cyan

foreach ($item in $ItemsToRemove) {
    [int64]$size = 0
    if ($item.PSIsContainer) {
        $files = Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue
        if ($files) {
            $size = ($files | Measure-Object -Property Length -Sum).Sum
        }
    } else {
        $size = $item.Length
    }
    $TotalBytes += $size
    $sizeMb = [math]::Round($size / 1MB, 2)
    Write-Host ("  - {0} ({1} MB)" -f $item.FullName, $sizeMb)

    if (-not $DryRun) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$TotalMb = [math]::Round($TotalBytes / 1MB, 2)
if ($DryRun) {
    Write-Host "`n[Dry-Run] Would free $TotalMb MB across $($ItemsToRemove.Count) item(s)." -ForegroundColor Yellow
} else {
    Write-Host "`nCleaned $($ItemsToRemove.Count) item(s) and freed $TotalMb MB!" -ForegroundColor Green
}
