$target = Join-Path $env:GITHUB_WORKSPACE "build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
if (-not (Test-Path $target)) { throw "Missing x86 fuzzer executable: $target" }
$bytes = [System.IO.File]::ReadAllBytes($target)
if ($bytes.Length -lt 64) { throw "Fuzzer executable is too small to be a valid PE image." }
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 64 -or ($peOffset + 6) -gt $bytes.Length) { throw "Invalid PE header offset: $peOffset" }
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($machine -ne 0x014c) { throw ("Expected I386 PE machine 0x014c, got 0x{0:X4}" -f $machine) }
Write-Host "Verified executable architecture: I386 (PE 0x014c)."
