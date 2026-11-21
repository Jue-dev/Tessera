# Windows backend mock validation

This Linux host-side harness compiles selected Tessera Windows backend control paths against a narrow, test-only Win32/PSAPI/Toolhelp/Detours API surface and deterministic stubs. It is not a Windows SDK, kernel, process loader, or replacement for a Windows/MSVC integration build.

## Run

    bash verify/windows_mock/run_windows_mock_tests.sh

The consolidated CI entry point runs the ordinary harness and its ASan/UBSan variant:

    bash .github/scripts/ci-windows-mock.sh

TSan is run independently by the quality workflow with SANITIZER_FLAGS=-fsanitize=thread.

## Covered behavior

Coverage includes process opening/access masks/architecture discovery; owned-handle cleanup; memory read/write/query/protection/flush ordering; partial transfers and pending-protection recovery; module enumeration and metadata; strict/best-effort thread suspension and resume; call-indexed Win32 failure injection; Detours transaction errors; and concurrency stress/shuffled tests.

Historical logs under verify/portable/logs/windows_mock_R8/ do not establish current-source behavior. Rebuild and run the harness on relevant changes. The windows_mock CI job and ASan/UBSan/TSan quality jobs all compile from source.
