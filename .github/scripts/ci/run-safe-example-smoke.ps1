$ErrorActionPreference = "Stop"
$examples = @(
    "artifacts/x64/Release/build/examples/tessera_example_01_scan_and_pe.exe",
    "artifacts/x64/Release/build/examples/tessera_example_03_rtti_and_reflection.exe",
    "artifacts/x64/Release/build/examples/tessera_example_04_blind_discovery.exe",
    "artifacts/x64/Release/build/examples/tessera_example_05_python_bridge.exe",
    "artifacts/x64/Release/build/examples/tessera_example_06_profiles_and_targets.exe"
)
foreach ($example in $examples) {
    if (-not (Test-Path $example)) { throw "Missing safe example executable: $example" }
    & $example
    if ($LASTEXITCODE -ne 0) { throw "Safe example smoke failed: $example" }
}
