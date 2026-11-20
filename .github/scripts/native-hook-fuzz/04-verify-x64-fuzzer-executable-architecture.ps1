$target = Join-Path $env:GITHUB_WORKSPACE "build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
if (-not (Test-Path $target)) { throw "Missing x64 fuzzer executable: $target" }
$bytes = [System.IO.File]::ReadAllBytes($target)
if ($bytes.Length -lt 64) { throw "Fuzzer executable is too small to be a valid PE image." }
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 64 -or ($peOffset + 6) -gt $bytes.Length) { throw "Invalid PE header offset: $peOffset" }
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($machine -ne 0x8664) { throw ("Expected AMD64 PE machine 0x8664, got 0x{0:X4}" -f $machine) }
Write-Host "Verified executable architecture: AMD64 (PE 0x8664)."
