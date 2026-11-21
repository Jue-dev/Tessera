param(
    [Parameter(Mandatory = $true)]
    [string]$DetoursRoot,
    [ValidateSet("x64", "x86")]
    [string]$Architecture = "x64",
    # Microsoft Detours v4.0.1's upstream NMake Makefile uses /MT (release CRT).
    # Keep this integration configuration aligned with that library build.
    [ValidateSet("Release")]
    [string]$Configuration = "Release",
    [string]$BuildDirectory = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$detoursRootResolved = (Resolve-Path $DetoursRoot).Path

$headerCandidates = @(
    (Join-Path $detoursRootResolved "src/detours.h"),
    (Join-Path $detoursRootResolved "include/detours.h"),
    (Join-Path $detoursRootResolved "include/detours/detours.h"),
    (Join-Path $detoursRootResolved "detours.h")
)
$header = $headerCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $header) {
    throw "Could not find detours.h under '$detoursRootResolved'."
}
$includeDir = Split-Path -Parent $header

$libraryCandidates = @(
    (Join-Path $detoursRootResolved "lib.$($Architecture.ToUpperInvariant())/detours.lib"),
    (Join-Path $detoursRootResolved "lib/$Architecture/detours.lib"),
    (Join-Path $detoursRootResolved "$Architecture/detours.lib"),
    (Join-Path $detoursRootResolved "detours.lib")
)
$library = $libraryCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $library) {
    throw "Could not find detours.lib for $Architecture under '$detoursRootResolved'. Provide a Detours build with architecture-specific library output."
}

# Directory naming alone is not proof of the library's machine type. Inspect
# the COFF members so an accidentally copied x86/x64 library fails before link.
$dumpbinOutput = & dumpbin /headers $library 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin could not inspect Detours library '$library':`n$dumpbinOutput"
}
$expectedMachine = if ($Architecture -eq "x86") { '14C machine \(x86\)' } else { '8664 machine \(x64\)' }
if ($dumpbinOutput -notmatch $expectedMachine) {
    throw "Detours library machine type does not match requested architecture '$Architecture'. Expected '$expectedMachine'."
}

if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $BuildDirectory = Join-Path $repoRoot "artifacts/detours-$Architecture/$Configuration"
}

$vsArch = if ($Architecture -eq "x86") { "Win32" } else { "x64" }
Write-Host "Tessera Detours integration validation"
Write-Host "  Architecture : $Architecture ($vsArch)"
Write-Host "  Configuration: $Configuration"
Write-Host "  Header       : $header"
Write-Host "  Library      : $library"
Write-Host "  Build        : $BuildDirectory"

cmake -S $repoRoot -B $BuildDirectory -G "Visual Studio 18 2026" -A $vsArch `
    -DTESSERA_WITH_DETOURS=ON `
    -DTESSERA_STATIC_RUNTIME=ON `
    -DTESSERA_BUILD_TESTS=ON `
    -DTESSERA_BUILD_EXAMPLES=OFF `
    -DTESSERA_WARNINGS_AS_ERRORS=ON `
    -DDETOURS_INCLUDE_DIRS="$includeDir" `
    -DDETOURS_LIBRARY="$library"
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)." }

cmake --build $BuildDirectory --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) { throw "Detours-enabled build failed ($LASTEXITCODE)." }

ctest --test-dir $BuildDirectory -C $Configuration --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "Detours-enabled CTest failed ($LASTEXITCODE)." }

# Validate the installed Detours-enabled SDK from an independent consumer.
# Explicit dependency paths model the SDK user supplying their Detours install.
$installPrefix = Join-Path $BuildDirectory "install"
$consumerBuild = Join-Path $BuildDirectory "installed-consumer"
cmake --install $BuildDirectory --config $Configuration --prefix $installPrefix
if ($LASTEXITCODE -ne 0) { throw "Detours-enabled SDK install failed ($LASTEXITCODE)." }

cmake -S (Join-Path $repoRoot "verify/tests/consumers/installed") -B $consumerBuild `
    -G "Visual Studio 18 2026" -A $vsArch `
    -DCMAKE_PREFIX_PATH="$installPrefix" `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    -DTESSERA_STATIC_RUNTIME=ON `
    -DDETOURS_INCLUDE_DIRS="$includeDir" `
    -DDETOURS_LIBRARY="$library"
if ($LASTEXITCODE -ne 0) { throw "Detours-enabled consumer configure failed ($LASTEXITCODE)." }

cmake --build $consumerBuild --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) { throw "Detours-enabled installed SDK consumer build failed ($LASTEXITCODE)." }

Write-Host "Detours-enabled build, CTest, install/export, and consumer validation passed."
Write-Host "Runtime library: /MT (matches the upstream Detours v4.0.1 NMake build)."
Write-Host "Note: the Detours-tagged test installs, calls, and removes a live hook in the test process."
