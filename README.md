# Tessera

Tessera is a modular C++23 SDK for Windows process-memory inspection, PE analysis, signature scanning, RTTI/reflection discovery, target profiles, and bounded x86/x64 inline hooks. It is distributed as a static library and keeps Windows headers out of its public umbrella header.

## Capabilities

- **Core and utilities:** strongly typed Address, RVA and range types, checked arithmetic, Result, JSON, strict text conversion, and atomic file operations.
- **Process and memory:** process metadata, IMemoryBackend, MemoryReader, transactional MemoryWriter, memory-region inspection, and ProtectionScope.
- **PE and scanning:** PE32/PE32+ parsing from memory or files, section/import/export metadata, signature scanning, cross-references, and address resolution.
- **RTTI and reflection:** MSVC virtual and non-virtual RTTI discovery, ObjectView, compiler-RTTI-independent type metadata, and Python bridge metadata discovery.
- **Runtime operations:** rollback-aware Patch/PatchTransaction and a native inline-hook backend alongside optional Microsoft Detours.
- **Profiles and targets:** profile persistence and fail-closed multi-build address verification.

Tessera keeps the SDK layering explicit: core and diagnostics are the foundation; process/memory and binary-analysis modules are separate; profile/target discovery builds on top. See the [architecture guide](docs/architecture.md), [API overview](docs/api.md), and [safety boundaries](docs/safety-and-boundaries.md).

## Build and test

Requirements: Windows 10/11, MSVC 19.38+ (Visual Studio 2022 17.8+ or Build Tools 18+), CMake 3.28+, and Ninja.

    cmake --preset x64-debug
    cmake --build --preset x64-debug
    ctest --preset x64-debug --output-on-failure

Available presets include x64/x86 Debug and Release, x64-asan, x64-analyze, x64-bench, and x64-fuzz-smoke. Detailed toolchain setup, options, installed SDK consumption, and configuration examples are in [docs/build.md](docs/build.md). The full development workflow and CI topology are in [docs/development-workflow.md](docs/development-workflow.md).

## SDK consumption

After installing a build, downstream CMake projects can use:

    find_package(Tessera CONFIG REQUIRED)
    target_link_libraries(my_app PRIVATE tessera::tessera)

The scripts/export_sdk.ps1 helper exports x64 Debug/Release packages; pass -AllArch to include x86. The SDK contains public headers, a single tessera.lib, CMake package files, and a Visual Studio property sheet.

## Examples

The examples directory contains six focused programs: PE scanning and resolution; patching and hooks; RTTI/reflection; blind binary discovery; Python bridge discovery; and profiles/targets. Default developer presets build these examples together with the tests.

## Verification and security

- CTest runs deterministic unit and fixture suites; a shuffled pass uses a fixed seed.
- verify/windows_mock exercises selected Windows backend control paths on Linux using test-only API stubs. It is not a Windows kernel or loader emulator.
- verify/fuzz contains eight deterministic corpus-replay harnesses. Coverage-guided campaigns additionally run the eight-target continuous matrix and x86/x64 native-hook fuzz jobs.
- The quality workflow retains clang-format, clang-tidy, ASan/UBSan, TSan, LLVM coverage, and CodeQL.
- Installed SDK consumers test package linking independently of the in-tree build.

The four GitHub Actions lifecycle workflows are [CI](.github/workflows/ci.yml), [quality](.github/workflows/quality.yml), [fuzz](.github/workflows/fuzz.yml), and [release](.github/workflows/release.yml). Release tags use v*.*.*. See [CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md).

## Supported boundary

Tessera targets the documented x86/x64 Windows process and binary-analysis model. The project does not add ARM64/WoW64 cross-architecture hosting, process injection/hosting or DLL loader techniques, VEH hooks, hardware breakpoints, or PAGE_GUARD hooks. Public API signatures and decisions in ADR 0001–0003 are compatibility boundaries.
