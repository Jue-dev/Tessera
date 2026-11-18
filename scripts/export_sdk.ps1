<#
.SYNOPSIS
    Builds Tessera and exports a unified, ready-to-use SDK folder (dist/TesseraSDK)
    containing include/, single-file tessera.lib, CMake package configs, and a
    Visual Studio MSBuild property sheet (Tessera.props) for 1-click integration.
.PARAMETER OutputDir
    Target directory for the exported SDK. Defaults to <repo>/dist/TesseraSDK.
.PARAMETER AllArch
    When set, builds and exports both x64 and x86 (Release + Debug). Otherwise exports x64 (Release + Debug).
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$AllArch
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $RepoRoot "dist\TesseraSDK"
}

Write-Host "=== Tessera SDK Exporter ===" -ForegroundColor Cyan
Write-Host "Output Directory: $OutputDir"

# Locate Visual Studio vcvars scripts
$VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$VcVars64 = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$VcVars32 = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

if ((Test-Path $VsWhere) -and -not (Test-Path $VcVars64)) {
    $InstallPath = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($InstallPath) {
        $VcVars64 = Join-Path $InstallPath "VC\Auxiliary\Build\vcvars64.bat"
        $VcVars32 = Join-Path $InstallPath "VC\Auxiliary\Build\vcvars32.bat"
    }
}

$Configs = @(
    @{ Preset = "x64-release"; Arch = "x64"; Config = "Release"; VcVars = $VcVars64 },
    @{ Preset = "x64-debug";   Arch = "x64"; Config = "Debug";   VcVars = $VcVars64 }
)
if ($AllArch) {
    $Configs += @(
        @{ Preset = "x86-release"; Arch = "x86"; Config = "Release"; VcVars = $VcVars32 },
        @{ Preset = "x86-debug";   Arch = "x86"; Config = "Debug";   VcVars = $VcVars32 }
    )
}

if (Test-Path -LiteralPath $OutputDir) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Push-Location $RepoRoot
try {
    foreach ($c in $Configs) {
        $preset = $c.Preset
        $arch   = $c.Arch
        $cfg    = $c.Config
        $vcvars = $c.VcVars
        $buildDir = Join-Path $RepoRoot "artifacts\$arch\$cfg\build"
        $stageDir = Join-Path $OutputDir "$arch\$cfg"

        Write-Host "`n-> Building & staging $preset ..." -ForegroundColor Cyan
        $cmd = "call `"$vcvars`" >nul && cmake --preset $preset && cmake --build --preset $preset --target tessera_static && cmake --install `"$buildDir`" --prefix `"$stageDir`""
        cmd /c $cmd
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build/install preset $preset"
        }
    }

    # Copy unified headers to <OutputDir>/include
    $FirstStageInclude = Join-Path $OutputDir "x64\Release\include"
    if (Test-Path $FirstStageInclude) {
        Copy-Item -Path $FirstStageInclude -Destination (Join-Path $OutputDir "include") -Recurse -Force
    }

    # Generate Visual Studio MSBuild Property Sheet (Tessera.props) for 1-click integration in .vcxproj
    $PropsPath = Join-Path $OutputDir "Tessera.props"
    $PropsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ImportGroup Label="PropertySheets" />
  <PropertyGroup Label="UserMacros">
    <TesseraSdkDir>`$(MSBuildThisFileDirectory)</TesseraSdkDir>
    <TesseraArch Condition="'`$(Platform)'=='x64'">x64</TesseraArch>
    <TesseraArch Condition="'`$(Platform)'=='Win32' Or '`$(Platform)'=='x86'">x86</TesseraArch>
    <TesseraConfig Condition="'`$(Configuration)'=='Debug'">Debug</TesseraConfig>
    <TesseraConfig Condition="'`$(Configuration)'!='Debug'">Release</TesseraConfig>
  </PropertyGroup>
  <ItemDefinitionGroup>
    <ClCompile>
      <AdditionalIncludeDirectories>`$(TesseraSdkDir)include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <LanguageStandard>stdcpplatest</LanguageStandard>
    </ClCompile>
    <Link>
      <AdditionalLibraryDirectories>`$(TesseraSdkDir)`$(TesseraArch)\`$(TesseraConfig)\lib;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>
      <AdditionalDependencies>tessera.lib;Psapi.lib;Shell32.lib;Ole32.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
</Project>
"@
    Set-Content -Path $PropsPath -Value $PropsXml -Encoding UTF8

    Write-Host "`n=== SDK Export Complete! ===" -ForegroundColor Green
    Write-Host "Headers       : $OutputDir\include"
    Write-Host "Single Libs   : $OutputDir\<x64|x86>\<Release|Debug>\lib\tessera.lib"
    Write-Host "VS PropSheet  : $PropsPath"
} finally {
    Pop-Location
}
