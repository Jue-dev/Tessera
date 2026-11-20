$ErrorActionPreference = "Stop"
$cmakeArgs = @(
  "-S", ".", "-B", "build-native-hook-fuzz", "-G", "Ninja",
  "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
  "-DCMAKE_C_COMPILER=clang-cl",
  "-DCMAKE_CXX_COMPILER=clang-cl",
  "-DCMAKE_CXX_STANDARD=23",
  "-DTESSERA_BUILD_TESTS=OFF",
  "-DTESSERA_BUILD_EXAMPLES=OFF",
  "-DTESSERA_BUILD_FUZZ=ON",
  "-DTESSERA_STATIC_RUNTIME=ON",
  "-DTESSERA_ENABLE_LIBFUZZER=ON"
)
& cmake @cmakeArgs
$configureExitCode = $LASTEXITCODE
if ($configureExitCode -ne 0) {
  $diagnosticLogs = @(
    "build-native-hook-fuzz/CMakeFiles/CMakeConfigureLog.yaml",
    "build-native-hook-fuzz/CMakeFiles/CMakeError.log",
    "build-native-hook-fuzz/CMakeFiles/CMakeOutput.log"
  )
  foreach ($logPath in $diagnosticLogs) {
    if (Test-Path $logPath) {
      Write-Host "===== $logPath ====="
      Get-Content $logPath -Tail 240
    }
  }
  throw "CMake configure failed for x64 ($configureExitCode)"
}
