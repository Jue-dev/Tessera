[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "x86")]
    [string]$Arch
)

$ErrorActionPreference = "Stop"
$RepoRoot = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
}

Push-Location $RepoRoot
try {
    $compiler = if ($Arch -eq "x64") { "clang-cl" } else { "cl" }
    $cmakeArgs = @(
        "-S", ".",
        "-B", "build-native-hook-fuzz",
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_C_COMPILER=$compiler",
        "-DCMAKE_CXX_COMPILER=$compiler",
        "-DCMAKE_CXX_STANDARD=23",
        "-DTESSERA_BUILD_TESTS=OFF",
        "-DTESSERA_BUILD_EXAMPLES=OFF",
        "-DTESSERA_BUILD_FUZZ=ON",
        "-DTESSERA_STATIC_RUNTIME=ON"
    )

    if ($Arch -eq "x64") {
        $cmakeArgs += "-DTESSERA_ENABLE_LIBFUZZER=ON"
    }
    else {
        $cmakeArgs += @(
            "-DTESSERA_ENABLE_ASAN=ON",
            "-DTESSERA_ENABLE_MSVC_FUZZER=ON"
        )
    }

    & cmake @cmakeArgs
    $configureExitCode = $LASTEXITCODE
    if ($configureExitCode -ne 0) {
        $diagnosticLogs = @(
            "build-native-hook-fuzz/CMakeFiles/CMakeOutput.log",
            "build-native-hook-fuzz/CMakeFiles/CMakeError.log"
        )
        foreach ($logPath in $diagnosticLogs) {
            if (Test-Path -LiteralPath $logPath) {
                Write-Host "===== $logPath ====="
                Get-Content -LiteralPath $logPath -Tail 240
            }
        }
        throw "CMake configure failed for $Arch ($configureExitCode)"
    }

    & cmake --build build-native-hook-fuzz --target tessera_fuzz_native_hook --parallel
    if ($LASTEXITCODE -ne 0) {
        throw "$Arch native-hook fuzzer build failed ($LASTEXITCODE)"
    }

    $target = Join-Path $RepoRoot "build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
    if (-not (Test-Path -LiteralPath $target)) {
        throw "Missing $Arch fuzzer executable: $target"
    }

    $bytes = [System.IO.File]::ReadAllBytes($target)
    if ($bytes.Length -lt 64) {
        throw "Fuzzer executable is too small to be a valid PE image."
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 64 -or ($peOffset + 6) -gt $bytes.Length) {
        throw "Invalid PE header offset: $peOffset"
    }

    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $expectedMachine = if ($Arch -eq "x64") { 0x8664 } else { 0x014c }
    if ($machine -ne $expectedMachine) {
        throw ("Expected {0} PE machine 0x{1:X4}, got 0x{2:X4}" -f $Arch, $expectedMachine, $machine)
    }
    $machineName = if ($Arch -eq "x64") { "AMD64" } else { "I386" }
    Write-Host "Verified executable architecture: $machineName (PE 0x$('{0:X4}' -f $machine))."
}
finally {
    Pop-Location
}
