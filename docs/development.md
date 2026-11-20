# Developer Workflow

## Build and test

Use the checked-in CMake presets from a Visual Studio Developer PowerShell/Command Prompt with the matching x64 or x86 environment:

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure
```

The x86/x64 Debug/Release presets use the same CMake options as the normal SDK build. Optional analysis, benchmark, and standalone fuzz-smoke configurations are separate presets; see [build instructions](build.md).

## Optional validation tools

- `x64-analyze`: MSVC static analysis.
- `x64-bench`: builds the scanner, decoder, and PE benchmark executables.
- `x64-fuzz-smoke`: builds standalone fuzz harnesses. Replay each executable against the matching `verify/fuzz/corpus/<harness>` directory with `-runs=100`.
- The independent x86 decoder differential job uses pinned, test-only `iced-x86==1.21.0`; it is not a runtime or SDK dependency.
- Native-hook x86/x64 coverage-guided fuzz campaigns are maintained in [native-hook-fuzz.yml](../.github/workflows/native-hook-fuzz.yml).

## Architecture constraints

- Preserve the public API under `include/tessera/**`; implementation-only helpers belong under `src/**`.
- Keep `core` and `profiling` as compiled targets and keep Python bridge implementation in the `rtti` target.
- Native inline-hook changes must preserve the safety, unwind, thread suspension, and lifecycle contract in [ADR 0002](adr/0002-native-inline-hook-safety-contract.md).
- Component dependencies and source-splitting constraints are recorded in [ADR 0003](adr/0003-core-profiling-and-rtti-boundaries.md).
- Run the full CI matrix before merging. Reduced SDK variants also install the package and compile a separate `find_package(Tessera CONFIG REQUIRED)` consumer.

## Repository map

- `include/tessera/**`: public SDK headers.
- `src/**`: private module implementations and internal helpers.
- `verify/tests/**`: deterministic tests and the optional decoder differential oracle.
- `verify/fuzz/**`: fuzz harnesses and checked-in seed corpora.
- `verify/bench/**`: opt-in benchmarks.
- `docs/adr/**`: accepted/proposed architecture decisions; archived hook records are historical context, not current validation evidence.
