param(
    [Parameter(Mandatory = $true)]
    [string]$Options
)

$ErrorActionPreference = "Stop"
$profileEnabled = if ($Options -match "TESSERA_BUILD_PROFILE=OFF") { 0 } else { 1 }
$targetsEnabled = if ($Options -match "TESSERA_BUILD_TARGETS=OFF") { 0 } else { 1 }
$consumerSource = Join-Path $env:GITHUB_WORKSPACE "verify/tests/consumers/standalone_consumer.cpp"
if (-not (Test-Path $consumerSource)) {
    throw "Shared standalone SDK consumer source not found: $consumerSource"
}

New-Item -ItemType Directory -Path consumer -Force | Out-Null
@'
cmake_minimum_required(VERSION 3.28)
project(TesseraInstalledConsumer LANGUAGES CXX)
find_package(Tessera CONFIG REQUIRED)
add_executable(tessera_consumer "${TESSERA_CONSUMER_SOURCE}")
target_link_libraries(tessera_consumer PRIVATE tessera::tessera)
target_compile_definitions(tessera_consumer PRIVATE
    TESSERA_STANDALONE_SDK_CONSUMER=1
    TESSERA_CONSUMER_WITH_PROFILE=${TESSERA_CONSUMER_WITH_PROFILE}
    TESSERA_CONSUMER_WITH_TARGETS=${TESSERA_CONSUMER_WITH_TARGETS})
'@ | Set-Content -Path consumer/CMakeLists.txt

$cmakeArguments = @(
    "-S", "consumer",
    "-B", "consumer/build",
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_PREFIX_PATH=$env:GITHUB_WORKSPACE\install-reduced",
    "-DTESSERA_CONSUMER_SOURCE=$consumerSource",
    "-DTESSERA_CONSUMER_WITH_PROFILE=$profileEnabled",
    "-DTESSERA_CONSUMER_WITH_TARGETS=$targetsEnabled"
)
& cmake @cmakeArguments
if ($LASTEXITCODE -ne 0) {
    throw "Installed SDK consumer configure failed ($LASTEXITCODE)."
}
cmake --build consumer/build --parallel
if ($LASTEXITCODE -ne 0) {
    throw "Installed SDK consumer build failed ($LASTEXITCODE)."
}
$consumerExecutable = Join-Path $PWD "consumer/build/tessera_consumer.exe"
& $consumerExecutable
if ($LASTEXITCODE -ne 0) {
    throw "Installed SDK consumer execution failed ($LASTEXITCODE)."
}
