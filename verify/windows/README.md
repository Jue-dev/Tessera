# Windows backend validation

## Microsoft Detours-enabled build and live hook test

The standard x86/x64 Debug/Release GitHub Actions matrix intentionally keeps the optional `TESSERA_WITH_DETOURS` dependency disabled. A separate `detours-integration` job now validates the real dependency on Windows for both x64 and x86:

1. Check out the official Microsoft Detours `v4.0.1` source.
2. Set up the matching Visual Studio target architecture.
3. Build Detours from `dependencies/Detours/src` with `nmake /nologo DETOURS_TARGET_PROCESSOR=X86` or `X64`; the v4.0.1 makefile does not consume `VSCMD_ARG_TGT_ARCH`.
4. Verify the generated `include/detours.h` and architecture-specific `lib.X64/detours.lib` or `lib.X86/detours.lib`.
5. Run `run_detours_integration.ps1`, which configures Tessera with `TESSERA_WITH_DETOURS=ON`, builds it, and runs CTest.

The Detours-enabled `tessera_test_patch_hook` suite verifies backend availability and runs a real in-process hook lifecycle: call the original target, attach Detours, dispatch through the detour and trampoline, detach, and confirm the original target behavior is restored. The test uses a deliberately non-inlined target with a volatile global read to keep a relocatable function body in optimized x86/x64 builds. It requests `ThreadPolicy::None` because the test invokes the target only from its own test thread.

The SDK release publication job depends on `detours-integration`, so a release cannot be published by this workflow if the real hook integration job fails.

For a manual run from a Visual Studio Developer PowerShell prompt after building Microsoft Detours for the same target architecture:

```powershell
.\verify\windows\run_detours_integration.ps1 -DetoursRoot C:\deps\Detours -Architecture x64 -Configuration Release
.\verify\windows\run_detours_integration.ps1 -DetoursRoot C:\deps\Detours -Architecture x86 -Configuration Release
```

This repository-side R8 change adds the CI job and test. The job has not yet executed in GitHub Actions from the current Linux environment; a successful local static audit is not a substitute for that Windows run.

### Runtime-library compatibility

Microsoft Detours v4.0.1's upstream `src/Makefile` compiles its static library with `/MT`. The integration script therefore configures Tessera with `TESSERA_STATIC_RUNTIME=ON` and deliberately supports the `Release` configuration only. This avoids MSVC `RuntimeLibrary` mismatch diagnostics (`LNK2038`) between Detours and the integration test executable. The normal Tessera SDK matrix remains on its independently configured default `/MD` runtime.
