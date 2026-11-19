[CmdletBinding()]
param(
    [string]$DetoursRoot = "",
    [switch]$RunFuzz,
    [ValidateSet(60, 300, 900)]
    [int]$FuzzSeconds = 300,
    [switch]$SkipWindowsMock
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$logs = Join-Path $root "artifacts/final-validation/logs"
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$summary = [System.Collections.Generic.List[object]]::new()

function Set-MsvcEnvironment([string]$arch) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio/Installer/vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw "vswhere not found: $vswhere" }
    $vs = & $vswhere -latest -products "*" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vs) { throw "Visual Studio/MSVC not found." }
    $vcvars = Join-Path $vs "VC/Auxiliary/Build/vcvarsall.bat"
    $cmdArch = if ($arch -eq "x64") { "amd64" } else { "x86" }
    $lines = & $env:ComSpec /d /s /c ('call "' + $vcvars + '" ' + $cmdArch + ' >nul && set')
    if ($LASTEXITCODE -ne 0) { throw "vcvarsall failed for $arch." }
    foreach ($line in $lines) {
        if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
        }
    }
    Write-Host "MSVC environment: $arch"
}

function Invoke-Logged([string]$name, [scriptblock]$command) {
    $log = Join-Path $logs ($name + ".log")
    Write-Host "`n===== $name ====="
    try {
        & $command 2>&1 | Tee-Object -FilePath $log
        if ($LASTEXITCODE -ne 0) { throw "$name failed with exit code $LASTEXITCODE" }
        $summary.Add([pscustomobject]@{ Stage = $name; Result = "PASS"; Log = $log })
    } catch {
        $summary.Add([pscustomobject]@{ Stage = $name; Result = "FAIL"; Log = $log })
        throw
    }
}

Push-Location $root
try {
    if (-not $SkipWindowsMock) {
        $mockCompiler = Get-Command g++ -ErrorAction SilentlyContinue
        if (-not $mockCompiler) { $mockCompiler = Get-Command clang++ -ErrorAction SilentlyContinue }
        $bash = Get-Command bash -ErrorAction SilentlyContinue
        if ($mockCompiler -and $bash) {
            Invoke-Logged "windows-mock" {
                bash ./verify/windows_mock/run_windows_mock_tests.sh
            }
        } else {
            Write-Warning "Windows mock skipped: bash and a host g++/clang++ are required. Run it from Linux/WSL separately."
            $summary.Add([pscustomobject]@{ Stage = "windows-mock"; Result = "SKIP"; Log = "No bash/host C++ compiler" })
        }
    }

    & ./verify/windows/generate_test_fixtures.ps1 -OutputDirectory ./verify/tests/fixtures
    if ($LASTEXITCODE -ne 0) { throw "Fixture generation failed." }

    foreach ($arch in @("x64", "x86")) {
        Set-MsvcEnvironment $arch
        foreach ($preset in @("$arch-debug", "$arch-release")) {
            Invoke-Logged $preset {
                cmake --preset $preset
                if ($LASTEXITCODE -ne 0) { throw "Configure failed: $preset" }
                cmake --build --preset $preset --parallel
                if ($LASTEXITCODE -ne 0) { throw "Build failed: $preset" }
                ctest --preset $preset --output-on-failure
                if ($LASTEXITCODE -ne 0) { throw "CTest failed: $preset" }
            }
        }
    }

    Set-MsvcEnvironment "x64"
    Invoke-Logged "msvc-analyze" {
        cmake --preset x64-analyze
        if ($LASTEXITCODE -ne 0) { throw "Analyze configure failed" }
        cmake --build --preset x64-analyze --parallel
        if ($LASTEXITCODE -ne 0) { throw "Analyze build failed" }
        ctest --preset x64-analyze --output-on-failure
        if ($LASTEXITCODE -ne 0) { throw "Analyze CTest failed" }
    }

    Invoke-Logged "no-rtti-fuzz-bench-package" {
        cmake -S . -B build-final-nortti -G Ninja -DCMAKE_BUILD_TYPE=Release -DTESSERA_BUILD_TESTS=ON -DTESSERA_BUILD_BENCH=ON -DTESSERA_BUILD_FUZZ=ON -DCMAKE_CXX_FLAGS="/GR-"
        if ($LASTEXITCODE -ne 0) { throw "No-RTTI configure failed" }
        cmake --build build-final-nortti --config Release --parallel
        if ($LASTEXITCODE -ne 0) { throw "No-RTTI build failed" }
        ctest --test-dir build-final-nortti -C Release --output-on-failure
        if ($LASTEXITCODE -ne 0) { throw "No-RTTI CTest failed" }
        $smokes = @(
            "build-final-nortti/verify/fuzz/tessera_fuzz_pattern.exe",
            "build-final-nortti/verify/fuzz/tessera_fuzz_pe.exe",
            "build-final-nortti/verify/fuzz/tessera_fuzz_json.exe",
            "build-final-nortti/verify/fuzz/tessera_fuzz_native_hook.exe",
            "build-final-nortti/verify/bench/tessera_bench.exe"
        )
        foreach ($exe in $smokes) {
            if (-not (Test-Path $exe)) { throw "Missing smoke executable: $exe" }
            & $exe
            if ($LASTEXITCODE -ne 0) { throw "Smoke executable failed: $exe" }
        }
        cmake --install build-final-nortti --config Release --prefix install-final-nortti
        if ($LASTEXITCODE -ne 0) { throw "Package install failed" }
    }

    if ($DetoursRoot) {
        foreach ($arch in @("x64", "x86")) {
            Set-MsvcEnvironment $arch
            $processor = if ($arch -eq "x86") { "X86" } else { "X64" }
            Push-Location (Join-Path $DetoursRoot "src")
            try {
                nmake /nologo "DETOURS_TARGET_PROCESSOR=$processor"
                if ($LASTEXITCODE -ne 0) { throw "Detours NMake build failed for $arch" }
            } finally {
                Pop-Location
            }
            Invoke-Logged "detours-$arch" {
                & ./verify/windows/run_detours_integration.ps1 -DetoursRoot $DetoursRoot -Architecture $arch -Configuration Release
                if ($LASTEXITCODE -ne 0) { throw "Detours integration failed: $arch" }
            }
        }
    } else {
        Write-Warning "Detours integration skipped. Supply -DetoursRoot to the Microsoft Detours v4.0.1 checkout."
        $summary.Add([pscustomobject]@{ Stage = "detours-x86-x64"; Result = "SKIP"; Log = "DetoursRoot not supplied" })
    }

    if ($RunFuzz) {
        Set-MsvcEnvironment "x64"
        Invoke-Logged "native-hook-libfuzzer-$FuzzSeconds" {
            cmake -S . -B build-final-native-hook-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DTESSERA_BUILD_TESTS=OFF -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_BUILD_FUZZ=ON -DTESSERA_STATIC_RUNTIME=ON -DTESSERA_ENABLE_LIBFUZZER=ON
            if ($LASTEXITCODE -ne 0) { throw "Fuzzer configure failed" }
            cmake --build build-final-native-hook-fuzz --target tessera_fuzz_native_hook --parallel
            if ($LASTEXITCODE -ne 0) { throw "Fuzzer build failed" }
            $resource = (clang-cl -print-resource-dir).Trim()
            $runtime = Join-Path $resource "lib/windows/clang_rt.asan_dynamic-x86_64.dll"
            if (-not (Test-Path $runtime)) { throw "ASan runtime missing: $runtime" }
            $target = Join-Path $root "build-final-native-hook-fuzz/verify/fuzz/tessera_fuzz_native_hook.exe"
            Copy-Item $runtime (Split-Path $target -Parent) -Force
            $artifact = Join-Path $root "artifacts/final-validation/native-hook-fuzz"
            $corpus = Join-Path $artifact "corpus"
            $crashes = Join-Path $artifact "crashes"
            New-Item -ItemType Directory -Force -Path $corpus, $crashes | Out-Null
            Copy-Item (Join-Path $root "verify/fuzz/corpus/native_hook/*") $corpus -Recurse -Force
            & $target $corpus "-max_total_time=$FuzzSeconds" "-timeout=10" "-max_len=96" "-rss_limit_mb=4096" "-seed=20261119" "-print_final_stats=1" "-artifact_prefix=$crashes/"
            if ($LASTEXITCODE -ne 0) { throw "libFuzzer failed: $LASTEXITCODE" }
        }
    } else {
        Write-Warning "Sustained libFuzzer campaign skipped. Use -RunFuzz when ready."
        $summary.Add([pscustomobject]@{ Stage = "native-hook-libfuzzer"; Result = "SKIP"; Log = "RunFuzz not supplied" })
    }
} finally {
    Pop-Location
    $summary | Format-Table -AutoSize | Out-String | Write-Host
    $summary | Export-Csv (Join-Path $logs "summary.csv") -NoTypeInformation
}
