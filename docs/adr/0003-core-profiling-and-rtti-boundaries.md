# ADR 0003: Core, Profiling, and RTTI Component Boundaries

- **Status**: Proposed
- **Date**: 2026-11-20
- **Related work**: Issue #22; `src/core/core.cpp`; `src/profiling/profiling.cpp`

## Context and inspected evidence

The source files reviewed on branch
`improve/stability-fuzzing-and-maintainability` are not both empty
placeholders:

- `src/core/core.cpp` includes compile-time assertions for the size and
  trivial-copyability guarantees of `Address`, `Rva`, and `ProcessId`.
  These assertions are build-time enforcement of public type invariants.
- `src/profiling/profiling.cpp` implements
  `profiling::run_benchmark`: zero-iteration/empty-callback handling,
  per-iteration timing, total/min/max accumulation, and mean calculation.
  It is executable library behavior, not an empty translation unit.
- `src/hook/backends/x86_instruction_decoder.hpp` contains the private
  bounded decoder implementation (approximately 21 KiB in the inspected
  revision). It is included by the native inline backend and currently has no
  public API role.
- `src/rtti/python_bridge.cpp` contains Python-runtime detection and bridge
  scanning logic, while `src/rtti/discovery.cpp` contains RTTI discovery and
  type reconstruction. They share the RTTI domain and some memory/scanning
  dependencies, but their responsibilities are distinct.

## Decision / recommendation

1. **Keep `tessera::core` as a compiled target.** Its translation unit
   enforces ABI/type invariants with compile-time assertions. Converting it to
   an INTERFACE target would require relocating those assertions into a
   guaranteed-compiled check target or another maintained mechanism. There is
   no meaningful build simplification that justifies that change now.
2. **Keep `tessera::profiling` as a compiled target.** It owns a concrete
   implementation used by consumers. It is not a placeholder and must not be
   converted to INTERFACE.
3. **Do not rename public `profile` or `profiling` header paths in this
   maintenance cycle.** The names are similar but describe different domains:
   persisted/configurable settings profiles versus timing/benchmark utilities.
   If a future rename is justified, use a compatibility period: introduce the
   new include path and namespace aliases, retain old headers as forwarding
   headers for at least one documented deprecation cycle, then remove only in
   a breaking release.
4. **Keep Python bridge discovery under `rtti` for now.** It operates on
   runtime metadata and memory inspection, so the current placement is
   coherent. A future extraction should be driven by a separate public
   capability boundary (for example, a dedicated optional Python integration
   component), not merely by file size. Such a change must first define target
   dependencies, feature-disable behavior, and public-header compatibility.
5. **Do not move the private x86 decoder solely to reduce header size without
   measuring compile-time impact and validating linkage.** Its implementation
   is private to the native hook backend today; a separate translation unit is
   a viable follow-up, but should be handled as its own behavior-preserving
   refactor with x86/x64 tests and benchmark/build evidence.

## Consequences

No target graph, public include path, namespace, or source file is changed by
this ADR. The recommendation avoids breaking downstream consumers and avoids
removing build-time invariants under the mistaken assumption that the files
are empty.

Before revisiting these decisions, inspect the current CMake target graph and
all link dependencies, then run the supported x86/x64 build and test matrix.
