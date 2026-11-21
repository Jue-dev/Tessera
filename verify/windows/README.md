# Windows backend validation

## Microsoft Detours integration

The standard MSVC x86/x64 Debug/Release matrix keeps TESSERA_WITH_DETOURS disabled. A separate x86/x64 Detours job checks out Microsoft Detours v4.0.1, builds the matching static library with NMake, verifies the architecture-specific artifact, and runs verify/windows/run_detours_integration.ps1.

CI invokes these consolidated tasks:
- ci-build.ps1 -Task detours -Action Build -Architecture x86|x64
- ci-build.ps1 -Task detours -Action Verify -Architecture x86|x64
- ci-build.ps1 -Task detours-integration -DetoursRoot path -Architecture x86|x64 -Configuration Release

Detours v4.0.1 builds with /MT; the integration script therefore uses TESSERA_STATIC_RUNTIME=ON and Release only. The live test calls the original target, attaches, dispatches through the detour/trampoline, detaches, and verifies restoration.

## Coverage and safety boundary

The four lifecycle workflows retain x86/x64 MSVC tests, /analyze, no-RTTI, Detours integration, independent decoder oracle, sanitizers, CodeQL, fuzzing, and SDK consumer checks. The Linux windows_mock harness tests selected backend control paths against deterministic test-only Win32/PSAPI/Toolhelp/Detours stubs; it does not emulate the Windows kernel or loader.

Native inline hooks are restricted to the supported x86/x64 implementation. Host quiescence, callback lifetime, and the one-backend-image-per-process requirement are documented in ADR 0002 and docs/native-inline-hooks.md.
