param(
 [Parameter(Mandatory=$true)][ValidateSet("configure","preset","detours","detours-integration")][string]$Task,
 [ValidateSet("NoRtti","Reduced")][string]$Mode="Reduced",
 [string]$Options="",
 [ValidateSet("x64-bench","x64-fuzz-smoke")][string]$Preset,
 [ValidateSet("Build","Verify")][string]$Action,
 [ValidateSet("x86","x64")][string]$Architecture="x64",
 [string]$DetoursRoot="",
 [ValidateSet("Release")][string]$Configuration="Release"
)
$ErrorActionPreference="Stop"
switch($Task){
 "configure" {
  if($Mode -eq "NoRtti"){
   $a=@("-S",".","-B","build-nortti","-G","Visual Studio 18 2026","-A","x64","-DTESSERA_BUILD_TESTS=ON","-DTESSERA_BUILD_BENCH=ON","-DTESSERA_BUILD_FUZZ=ON","-DTESSERA_ENABLE_MSVC_FUZZER=ON","-DTESSERA_ENABLE_ASAN=ON","-DTESSERA_STATIC_RUNTIME=ON","-DTESSERA_PATTERN_FORCE_SCALAR=ON","-DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=ProgramDatabase","-DCMAKE_CXX_FLAGS=/GR-")
  }else{
   $a=@("-S",".","-B","build-reduced","-G","Ninja","-DCMAKE_BUILD_TYPE=Release","-DTESSERA_BUILD_TESTS=OFF","-DTESSERA_BUILD_EXAMPLES=OFF")
   if($Options){$a+=@($Options -split "\s+" | Where-Object {$_})}
  }
  & cmake @a
  if($LASTEXITCODE -ne 0){throw "CMake configure failed ($LASTEXITCODE)."}
 }
 "preset" {
  if(-not $Preset){throw "-Preset is required."}
  & cmake --preset $Preset
  if($LASTEXITCODE -ne 0){throw "Preset configure failed."}
  & cmake --build --preset $Preset --parallel
  if($LASTEXITCODE -ne 0){throw "Preset build failed."}
  & ctest --preset $Preset --output-on-failure
  if($LASTEXITCODE -ne 0){throw "Preset tests failed."}
 }
 "detours" {
  if(-not $Action){throw "-Action is required."}
  $arch=if($Architecture -eq "x86"){"X86"}else{"X64"}
  if($Action -eq "Build"){
   & nmake /nologo "DETOURS_TARGET_PROCESSOR=$arch"
   if($LASTEXITCODE -ne 0){throw "Detours build failed."}
  }else{
   $root=if($env:GITHUB_WORKSPACE){$env:GITHUB_WORKSPACE}else{(Get-Location).Path}
   $lib=Join-Path $root "dependencies/Detours/lib.$arch/detours.lib"
   $hdr=Join-Path $root "dependencies/Detours/include/detours.h"
   if(!(Test-Path $lib) -or !(Test-Path $hdr)){throw "Detours $arch outputs are incomplete."}
  }
 }
 "detours-integration" {
  if(-not $DetoursRoot){throw "-DetoursRoot is required."}
  & .\verify\windows\run_detours_integration.ps1 -DetoursRoot $DetoursRoot -Architecture $Architecture -Configuration $Configuration
  if($LASTEXITCODE -ne 0){throw "Detours integration failed."}
 }
}