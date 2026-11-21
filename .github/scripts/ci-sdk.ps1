param(
 [Parameter(Mandatory=$true)][ValidateSet("package-bundle","package-release","checksum","validate","consumer")][string]$Task,
 [string]$ArchivePath=".\Tessera-SDK-Windows.zip",[string]$ChecksumPath=".\SHA256SUMS.txt",
 [string]$ReleaseTag="",[string]$SdkPrefix=".\install-reduced",[string]$Options=""
)
$ErrorActionPreference="Stop"
$root=(Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
function New-Checksum([string]$p,[string]$out){
 if(!(Test-Path $p)){throw "Missing archive $p"};if((Get-Item $p).Length -le 0){throw "Empty archive"}
 $h=(Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant()
 "$h  $([IO.Path]::GetFileName($p))"|Out-File $out -Encoding ascii
}
function Test-Archive([string]$p,[string]$sum){
 $line=(Get-Content $sum -Raw).Trim();$n=[IO.Path]::GetFileName($p)
 if($line -notmatch ('^(?<hash>[0-9a-fA-F]{64})  '+[regex]::Escape($n)+'$')){throw "Invalid checksum manifest"}
 $actual=(Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant();if($Matches.hash.ToLowerInvariant() -ne $actual){throw "Archive checksum mismatch"}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $zip=[IO.Compression.ZipFile]::OpenRead((Resolve-Path $p).Path)
 try{$names=@($zip.Entries|%{$_.FullName.Replace('\','/')});$required=@("include/tessera/tessera.hpp","x64/Release/lib/tessera.lib","x64/Debug/lib/tessera.lib","x86/Release/lib/tessera.lib","x86/Debug/lib/tessera.lib","x64/Release/lib/cmake/Tessera/TesseraConfig.cmake","x64/Debug/lib/cmake/Tessera/TesseraConfig.cmake","x86/Release/lib/cmake/Tessera/TesseraConfig.cmake","x86/Debug/lib/cmake/Tessera/TesseraConfig.cmake");$missing=@($required|?{$_ -notin $names});if($missing.Count){throw "Archive missing: $($missing -join ', ')"}}
 finally{$zip.Dispose()}
}
switch($Task){
 "package-bundle" {
  New-Item -ItemType Directory TesseraSDK -Force|Out-Null;Copy-Item include TesseraSDK/include -Recurse -Force
  foreach($preset in @("x64-release","x64-debug","x86-release","x86-debug")){$a=$preset.Split("-")[0];$c=if($preset.EndsWith("debug")){"Debug"}else{"Release"};$src="sdk-Input/Tessera-SDK-$preset";$dst="TesseraSDK/$a/$c";if(!(Test-Path $src)){throw "Missing SDK input $src"};New-Item -ItemType Directory $dst -Force|Out-Null;Copy-Item "$src/*" $dst -Recurse -Force}
  if(Test-Path $ArchivePath){Remove-Item $ArchivePath -Force};Compress-Archive TesseraSDK/* $ArchivePath -Force;New-Checksum $ArchivePath $ChecksumPath;Test-Archive $ArchivePath $ChecksumPath
 }
 "package-release" {
  if(!$ReleaseTag){throw "-ReleaseTag is required"};$sdk=Join-Path $root "dist/TesseraSDK"
  & (Join-Path $root "scripts/export_sdk.ps1") -AllArch -OutputDir $sdk;if($LASTEXITCODE -ne 0){throw "SDK export failed"}
  $ArchivePath="Tessera-SDK-$ReleaseTag.zip";Compress-Archive (Join-Path $sdk "*") $ArchivePath -CompressionLevel Optimal -Force;$ChecksumPath="SHA256SUMS.txt";New-Checksum $ArchivePath $ChecksumPath;Test-Archive $ArchivePath $ChecksumPath
 }
 "checksum"{New-Checksum $ArchivePath $ChecksumPath}
 "validate"{Test-Archive $ArchivePath $ChecksumPath}
 "consumer" {
  $profile=if($Options -match "TESSERA_BUILD_PROFILE=OFF"){0}else{1};$targets=if($Options -match "TESSERA_BUILD_TARGETS=OFF"){0}else{1}
  $src=Join-Path $root "verify/tests/consumers/standalone_consumer.cpp";if(!(Test-Path $src)){throw "Standalone consumer source missing"}
  New-Item -ItemType Directory consumer -Force|Out-Null
  @"
cmake_minimum_required(VERSION 3.28)
project(TesseraInstalledConsumer LANGUAGES CXX)
find_package(Tessera CONFIG REQUIRED)
add_executable(tessera_consumer "$($src.Replace('\','/'))")
target_link_libraries(tessera_consumer PRIVATE tessera::tessera)
target_compile_definitions(tessera_consumer PRIVATE TESSERA_STANDALONE_SDK_CONSUMER=1 TESSERA_CONSUMER_WITH_PROFILE=$profile TESSERA_CONSUMER_WITH_TARGETS=$targets)
"@|Set-Content consumer/CMakeLists.txt
  cmake -S consumer -B consumer/build -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$SdkPrefix";if($LASTEXITCODE -ne 0){throw "Consumer configure failed"}
  cmake --build consumer/build --parallel;if($LASTEXITCODE -ne 0){throw "Consumer build failed"}
  & .\consumer\build\tessera_consumer.exe;if($LASTEXITCODE -ne 0){throw "Consumer run failed"}
 }
}