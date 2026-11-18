[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"

function Resolve-LlvmTool([string]$Name) {
    # Prefer the LLVM toolchain shipped with the selected Visual Studio
    # installation. PATH may contain a different (and incompatible) LLVM.
    $candidates = @()
    if ($env:VCINSTALLDIR) {
        $candidates += (Join-Path $env:VCINSTALLDIR "Tools/Llvm/bin/$Name.exe")
        $candidates += (Join-Path $env:VCINSTALLDIR "Tools/Llvm/x64/bin/$Name.exe")
    }

    $command = Get-Command "${Name}.exe" -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
    $candidates += "C:/Program Files/LLVM/bin/$Name.exe"

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    throw "Required LLVM tool '${Name}.exe' was not found. Run this script from an MSVC developer environment with Visual Studio LLVM tools installed."
}

function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
    Write-Host ">> $Executable $($Arguments -join ' ')"
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Executable"
    }
}

$clangCl = Resolve-LlvmTool "clang-cl"
$clang = Resolve-LlvmTool "clang"
$lldLink = Resolve-LlvmTool "lld-link"

$clangVersion = (& $clangCl --version 2>&1 | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or $clangVersion -notmatch 'clang version\s+(\d+)') {
    throw "Unable to determine the clang-cl version from '$clangCl'. Output: $clangVersion"
}
$clangMajor = [int]$Matches[1]
$minimumClangMajor = 17
if ($env:VCToolsVersion -match '^14\.(\d+)\.') {
    if ([int]$Matches[1] -ge 52) { $minimumClangMajor = 22 }
}
if ($clangMajor -lt $minimumClangMajor) {
    throw "Incompatible clang-cl version $clangMajor at '$clangCl'. MSVC toolset $env:VCToolsVersion requires Clang $minimumClangMajor or newer. The Visual Studio LLVM toolchain is preferred over a global PATH installation."
}
Write-Host "Using $clangVersion ($clangCl) with MSVC toolset $env:VCToolsVersion."

$fixtureSource = Join-Path $PSScriptRoot "../tests/fixtures"
$fixtureSource = [System.IO.Path]::GetFullPath($fixtureSource)
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("tessera-fixtures-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    function Build-PeFixture(
        [string]$Name,
        [string]$Triple,
        [string]$Machine,
        [string]$CppFile,
        [string]$AsmFile,
        [string[]]$Exports
    ) {
        $cpp = Join-Path $fixtureSource $CppFile
        $asm = Join-Path $fixtureSource $AsmFile
        $cppObject = Join-Path $temp "${Name}.obj"
        $asmObject = Join-Path $temp "${Name}-vftable.obj"
        $dll = Join-Path $output "${Name}.dll"

        $compileArgs = @(
            "--target=$Triple", "/nologo", "/c", "/GR", "/EHs-c-", "/Zl", "/GS-"
        )
        if ($Name -eq "rtti_fixture_x64") {
            # The reconstruction regression needs a stack-spilling function with
            # x64 unwind metadata, so keep this fixture's exported leaf unoptimized.
            $compileArgs += @("/Od", "/Ob0")
        } else {
            $compileArgs += "/O1"
        }
        $compileArgs += @("/std:c++latest", "/Fo$cppObject", $cpp)
        Invoke-Checked $clangCl $compileArgs
        Invoke-Checked $clang @("--target=$Triple", "-c", $asm, "-o", $asmObject)

        $linkArgs = @(
            "/dll", "/noentry", "/nodefaultlib", "/noimplib",
            "/machine:$Machine", "/out:$dll", $cppObject, $asmObject
        )
        if ($Machine -eq "x86") { $linkArgs += "/safeseh:no" }
        foreach ($export in $Exports) { $linkArgs += "/export:$export" }
        Invoke-Checked $lldLink $linkArgs

        if (-not (Test-Path $dll) -or (Get-Item $dll).Length -le 1024) {
            throw "Generated PE fixture '$dll' is missing or unexpectedly small."
        }
        Write-Host "Generated $dll ($((Get-Item $dll).Length) bytes)"
    }

    Build-PeFixture "rtti_fixture_x64" "x86_64-pc-windows-msvc" "x64" "rtti_fixture_x64.cpp" "rtti_typeinfo_vftable_x64.s" @("make_base", "make_vbase", "get_plain_type", "sum_plain", "read_derived")
    Build-PeFixture "rtti_fixture_x86" "i686-pc-windows-msvc" "x86" "rtti_fixture_x86.cpp" "rtti_typeinfo_vftable_x86.s" @("as_base", "as_vbase")
    Build-PeFixture "rtti_virtual_branch_x64" "x86_64-pc-windows-msvc" "x64" "rtti_virtual_branch_fixture.cpp" "rtti_typeinfo_vftable_x64.s" @("as_virtual_base", "as_virtual_left", "as_virtual_right")
    Build-PeFixture "rtti_virtual_branch_x86" "i686-pc-windows-msvc" "x86" "rtti_virtual_branch_fixture.cpp" "rtti_typeinfo_vftable_x86.s" @("as_virtual_base", "as_virtual_left", "as_virtual_right")
}
finally {
    if (Test-Path $temp) {
        Remove-Item -Recurse -Force $temp
    }
}
