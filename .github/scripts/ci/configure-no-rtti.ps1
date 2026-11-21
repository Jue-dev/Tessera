$ErrorActionPreference = "Stop"
$cmakeArguments = @(
    "-S", ".",
    "-B", "build-nortti",
    "-G", "Visual Studio 18 2026",
    "-A", "x64",
    "-DTESSERA_BUILD_TESTS=ON",
    "-DTESSERA_BUILD_BENCH=ON",
    "-DTESSERA_BUILD_FUZZ=ON",
    "-DTESSERA_ENABLE_MSVC_FUZZER=ON",
    "-DTESSERA_ENABLE_ASAN=ON",
    "-DTESSERA_STATIC_RUNTIME=ON",
    "-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=ProgramDatabase",
    "-DCMAKE_CXX_FLAGS=/GR-"
)
& cmake @cmakeArguments
if ($LASTEXITCODE -ne 0) {
    throw "No-RTTI CMake configure failed ($LASTEXITCODE)."
}
