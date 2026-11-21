param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("NoRtti", "Reduced")]
    [string]$Mode,

    [string]$Options = ""
)

$ErrorActionPreference = "Stop"
if ($Mode -eq "NoRtti") {
    $cmakeArguments = @(
        "-S", ".", "-B", "build-nortti",
        "-G", "Visual Studio 18 2026", "-A", "x64",
        "-DTESSERA_BUILD_TESTS=ON",
        "-DTESSERA_BUILD_BENCH=ON",
        "-DTESSERA_BUILD_FUZZ=ON",
        "-DTESSERA_ENABLE_MSVC_FUZZER=ON",
        "-DTESSERA_ENABLE_ASAN=ON",
        "-DTESSERA_STATIC_RUNTIME=ON",
        "-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=ProgramDatabase",
        "-DCMAKE_CXX_FLAGS=/GR-"
    )
} else {
    $cmakeArguments = @(
        "-S", ".", "-B", "build-reduced",
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DTESSERA_BUILD_TESTS=OFF",
        "-DTESSERA_BUILD_EXAMPLES=OFF"
    )
    if (-not [string]::IsNullOrWhiteSpace($Options)) {
        $cmakeArguments += @($Options -split "\s+" | Where-Object { $_ -ne "" })
    }
}

& cmake @cmakeArguments
if ($LASTEXITCODE -ne 0) {
    throw "$Mode CMake configure failed ($LASTEXITCODE)."
}
