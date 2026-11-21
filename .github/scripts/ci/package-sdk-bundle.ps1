$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path "TesseraSDK" -Force | Out-Null
Copy-Item -Path "include" -Destination "TesseraSDK\include" -Recurse -Force
foreach ($preset in @("x64-release", "x64-debug", "x86-release", "x86-debug")) {
    $parts = $preset.Split("-")
    $arch = $parts[0]
    $configuration = if ($parts[1] -eq "debug") { "Debug" } else { "Release" }
    $sourceDirectory = "sdk-Input\Tessera-SDK-$preset"
    $destinationDirectory = "TesseraSDK\$arch\$configuration"
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item -Path "$sourceDirectory\*" -Destination $destinationDirectory -Recurse -Force
}
Compress-Archive -Path "TesseraSDK\*" -DestinationPath "Tessera-SDK-Windows.zip" -Force
