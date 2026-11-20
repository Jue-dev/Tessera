$ErrorActionPreference = "Stop"
$clang = Get-Command clang-cl -ErrorAction Stop
Write-Host "Using clang-cl: $($clang.Source)"
clang-cl --version
if ($LASTEXITCODE -ne 0) { throw "clang-cl version check failed ($LASTEXITCODE)" }
clang-cl "--target=x86_64-pc-windows-msvc" -v
if ($LASTEXITCODE -ne 0) { throw "clang-cl x64 target check failed ($LASTEXITCODE)" }

$resource = (clang-cl -print-resource-dir).Trim()
if ($LASTEXITCODE -ne 0 -or -not $resource) { throw "Unable to locate Clang resource directory." }
$runtimeDir = Join-Path $resource "lib/windows"
$required = @(
  "clang_rt.fuzzer-x86_64.lib",
  "clang_rt.asan_dynamic-x86_64.lib",
  "clang_rt.asan_static_runtime_thunk-x86_64.lib",
  "clang_rt.asan_dynamic-x86_64.dll"
)
foreach ($name in $required) {
  $path = Join-Path $runtimeDir $name
  if (-not (Test-Path $path)) { throw "Missing required x64 Clang runtime: $path" }
  Write-Host "Found: $name"
}
