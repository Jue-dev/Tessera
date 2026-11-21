param([Parameter(Mandatory=$true)][ValidateSet("setup","build","run")][string]$Stage,[Parameter(Mandatory=$true)][ValidateSet("x64","x86")][string]$Arch)
$ErrorActionPreference="Stop";$root=$env:GITHUB_WORKSPACE
if(!$root){$root=(Resolve-Path (Join-Path $PSScriptRoot "../..")).Path}
Push-Location $root
try{
 switch($Stage){
 "setup"{
  if($Arch -eq "x64"){
   $clang=(Get-Command clang-cl -ErrorAction Stop).Source;& $clang --version;if($LASTEXITCODE -ne 0){throw "clang-cl unavailable"}
   $resource=(& $clang -print-resource-dir).Trim();$dir=Join-Path $resource "lib/windows"
   foreach($f in @("clang_rt.fuzzer-x86_64.lib","clang_rt.asan_dynamic-x86_64.lib","clang_rt.asan_static_runtime_thunk-x86_64.lib","clang_rt.asan_dynamic-x86_64.dll")){if(!(Test-Path (Join-Path $dir $f))){throw "Missing Clang runtime $f"}}
  }else{
   if($env:VSCMD_ARG_TGT_ARCH -ne "x86"){throw "MSVC target is not x86"}
   $probe=Join-Path $env:RUNNER_TEMP "fuzzer_probe.cpp";$exe=Join-Path $env:RUNNER_TEMP "fuzzer_probe.exe"
   @'
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,std::size_t size){volatile auto v=size?data[0]:0;(void)v;return 0;}
'@|Set-Content $probe -Encoding ascii
   cl /nologo /std:c++latest /EHsc /MT /fsanitize=address /fsanitize=fuzzer $probe "/Fe:$exe";if($LASTEXITCODE -ne 0){throw "MSVC x86 fuzzer probe build failed"}
   & $exe "-runs=8";if($LASTEXITCODE -ne 0){throw "MSVC x86 fuzzer probe failed"}
   $dll=$null;foreach($r in @($env:VCToolsInstallDir,$env:VCToolsRedistDir)){if($r -and (Test-Path $r)){$m=Get-ChildItem $r -Filter clang_rt.asan_dynamic-i386.dll -Recurse -File -EA SilentlyContinue|Select-Object -First 1;if($m){$dll=$m.FullName;break}}}
   if(!$dll){throw "x86 ASan runtime DLL missing"};$d=Join-Path $root "build-native-hook-fuzz/verify/fuzz";New-Item -ItemType Directory $d -Force|Out-Null;Copy-Item $dll $d -Force
  }
 }
 "build"{
  $compiler=if($Arch -eq "x64"){"clang-cl"}else{"cl"}
  $a=@("-S",".","-B","build-native-hook-fuzz","-G","Ninja","-DCMAKE_BUILD_TYPE=RelWithDebInfo","-DCMAKE_C_COMPILER=$compiler","-DCMAKE_CXX_COMPILER=$compiler","-DCMAKE_CXX_STANDARD=23","-DTESSERA_BUILD_TESTS=OFF","-DTESSERA_BUILD_EXAMPLES=OFF","-DTESSERA_BUILD_FUZZ=ON","-DTESSERA_STATIC_RUNTIME=ON")
  if($Arch -eq "x64"){$a+="-DTESSERA_ENABLE_LIBFUZZER=ON"}else{$a+=@("-DTESSERA_ENABLE_ASAN=ON","-DTESSERA_ENABLE_MSVC_FUZZER=ON")}
  & cmake @a;if($LASTEXITCODE -ne 0){throw "Fuzzer configure failed"};cmake --build build-native-hook-fuzz --target tessera_fuzz_native_hook --parallel;if($LASTEXITCODE -ne 0){throw "Fuzzer build failed"}
  $exe="build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe";$b=[IO.File]::ReadAllBytes($exe);$off=[BitConverter]::ToInt32($b,0x3c);$mach=[BitConverter]::ToUInt16($b,$off+4);$expected=if($Arch -eq "x64"){0x8664}else{0x014c};if($mach -ne $expected){throw "Built fuzzer architecture mismatch"}
 }
 "run"{
  if($env:CAMPAIGN_SECONDS -notin @("300","600","900")){throw "Unsupported campaign duration"}
  $artifact="artifacts/native-hook-fuzz/$Arch";$corpus="$artifact/corpus";$crashes="$artifact/crashes";New-Item -ItemType Directory $corpus,$crashes -Force|Out-Null
  if(@(Get-ChildItem verify/fuzz/corpus/native_hook -File).Count -eq 0){throw "Empty native-hook corpus"};Copy-Item verify/fuzz/corpus/native_hook/* $corpus -Recurse -Force
  $exe="build-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe";if(!(Test-Path $exe)){throw "Fuzzer not built"}
  if($Arch -eq "x64"){$clang=(Get-Command clang-cl -EA Stop).Source;$res=(& $clang -print-resource-dir).Trim();Copy-Item (Join-Path $res "lib/windows/clang_rt.asan_dynamic-x86_64.dll") (Split-Path $exe) -Force}
  elseif(!(Test-Path (Join-Path (Split-Path $exe) "clang_rt.asan_dynamic-i386.dll"))){throw "x86 ASan DLL unstaged"}
  $log="$artifact/campaign.log";$rss=if($Arch -eq "x64"){4096}else{1024}
  & $exe $corpus "-max_total_time=$env:CAMPAIGN_SECONDS" "-timeout=10" "-max_len=96" "-rss_limit_mb=$rss" "-seed=20261119" "-print_final_stats=1" "-artifact_prefix=$crashes/" 2>&1|Tee-Object $log
  if($LASTEXITCODE -ne 0){throw "Native-hook fuzz failed"};$txt=Get-Content $log -Raw
  if($txt -notmatch "stat::number_of_executed_units:\s*[1-9][0-9]*"){throw "Fuzzer reports no executions"}
  $summary=[regex]::Match($txt,"(?m)^Done\s+([0-9,]+)\s+runs\s+in\s+([0-9]+)\s+second");if(!$summary.Success){throw "Missing fuzz summary"}
  $runs=[uint64](($summary.Groups[1].Value -replace ",",""));$sec=[int]$summary.Groups[2].Value
  if($runs -lt 100000 -or $sec -lt ([int]$env:CAMPAIGN_SECONDS-5)){throw "Fuzz campaign under-ran"}
  if($Arch -eq "x86" -and $txt -notmatch "DONE\s+ft:\s*[1-9][0-9]*"){throw "x86 coverage features missing"}
 }
 }
}finally{Pop-Location}
