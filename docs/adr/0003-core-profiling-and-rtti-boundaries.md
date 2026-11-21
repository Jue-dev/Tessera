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
- The private bounded x86/x64 decoder was originally under
  `src/hook/backends/` and used by the native inline backend only. Wave 3
  relocates it to `src/disasm/` because scanner/xref and resolver now need the
  same conservative instruction-boundary and operand metadata. It remains an
  internal implementation with no public API role.
  The native hook backend keeps a two-line private forwarding include at its
  historical local include path; the decoder implementation and canonical
  internal header are owned by `src/disasm/`.
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
5. **Keep the x86 decoder internal and below its consumers.** It was initially
   hook-private; once scanner/xref and resolver required the same bounded
   decoding semantics, Wave 3 moved it into the private `disasm` build component.
   The move is behavior-preserving, does not add an installed target or public
   header, and must retain x86/x64 decoder-oracle and native-hook validation.

## Consequences

No target graph, public include path, namespace, or source file is changed by
this ADR. The recommendation avoids breaking downstream consumers and avoids
removing build-time invariants under the mistaken assumption that the files
are empty.

Before revisiting these decisions, inspect the current CMake target graph and
all link dependencies, then run the supported x86/x64 build and test matrix.
