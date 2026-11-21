$ErrorActionPreference = "Stop"
& .\.github\scripts\ci\package-sdk-bundle.ps1
if (-not (Test-Path ".\Tessera-SDK-Windows.zip")) {
    throw "SDK packaging did not create Tessera-SDK-Windows.zip."
}
& .\.github\scripts\ci\create-sdk-checksum.ps1
& .\.github\scripts\ci\validate-sdk-archive.ps1
