param(
    [Parameter(Mandatory = $true)]
    [string]$Options
)

$ErrorActionPreference = "Stop"
$cmakeArguments = @(
    "-S", ".",
    "-B", "build-reduced",
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DTESSERA_BUILD_TESTS=OFF",
    "-DTESSERA_BUILD_EXAMPLES=OFF"
)
if (-not [string]::IsNullOrWhiteSpace($Options)) {
    $cmakeArguments += @($Options -split "\s+" | Where-Object { $_ -ne "" })
}
& cmake @cmakeArguments
if ($LASTEXITCODE -ne 0) {
    throw "Reduced SDK CMake configure failed ($LASTEXITCODE)."
}
