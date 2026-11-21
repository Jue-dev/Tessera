# Tessera API Overview

## Error Handling (`Result<T>` and `Status`)

All fallible operations return `tessera::Result<T>` (`std::expected<T, tessera::Error>`) or `tessera::Status` (`std::expected<void, tessera::Error>`). No exceptions escape any public API boundary.

## Address Types & Resolution

- `tessera::Address`: Strongly-typed absolute virtual address (`uint64_t`).
- `tessera::Rva`: Relative virtual address (`uint32_t`).
- `tessera::ProcessAddress`: Binds a `MemoryReader` with an `Address`. Supports:
  - Fluent dot-chaining via `.cursor()`:
    ```cpp
    auto res = paddr.cursor().offset(3).follow_rip().deref().unwrap();
    ```
  - Pipe composition via `tessera::resolve::*`:
    ```cpp
    auto res = paddr | tessera::resolve::add(3)
                     | tessera::resolve::follow_rip()
                     | tessera::resolve::deref();
    ```

## Compile-Time Patterns

```cpp
using namespace tessera::literals;
constexpr auto pat = "48 8B 05 ? ? ? ? 48 85 C0"_sig;
```

## Target Profiles (`tessera::targets`)

`AddressResolver` enforces the **Fail-Closed Verification Contract**: an `std::optional<VerifiedAddress>` is populated if and only if the resolved address passes all configured `ValidationRule` checks (`ModuleRange`, `Section`, `MemoryExecutable`, `ExpectedBytes`, `SecondarySignature`, `PointerSanity`).

Supported `ResolutionStrategy` modes:
- `Rva`, `Export`, `Pattern`, `PointerChain`, `Relative`, `Field`
- `RttiVTable`: Resolves a class `vftable` or specific virtual method slot by class name (`"Game::Player"`).
- `StringXref`: Resolves code referencing a specific string literal.
- `PythonMethod`: Resolves a C++ function registered via `PyMethodDef` (`"net.SendChatPacket"`), even when CPython is statically embedded into the `.exe`.

## RTTI, Blind Discovery & Python Bridge (`tessera::rtti`)

```cpp
// 1. Discover all polymorphic classes & vtables
auto rtti_cat = tessera::rtti::RttiCatalog::discover_all(proc, mod_range);

// 2. Discover non-virtual structs, functions, and reconstruct struct fields
auto all_tds = tessera::rtti::BinaryExplorer::scan_all_type_descriptors(proc, mod_range, &(*rtti_cat));
auto recon   = tessera::rtti::BinaryExplorer::reconstruct_struct(proc, fn_range, "Game::ActorData");

// 3. Discover DLL or Statically-Embedded (.exe) Python bindings
auto py_cat  = tessera::rtti::PythonBridgeScanner::discover_all(proc, mod_range);
auto fn      = py_cat->find_method("net.SendChatPacket");
```


## Public module entry points

The umbrella header `tessera/tessera.hpp` includes the primary public modules. Applications may include narrower headers when they want an explicit dependency boundary.

| Area | Public entry points |
| --- | --- |
| Process and memory | `Process`, `IMemoryBackend`, `MemoryReader`, `MemoryWriter`, `ProtectionScope`, `read_scatter`, `MemorySnapshot`, `diff` |
| PE/module inspection | `PeImage` raw/mapped readers, read-only `PeFileBackend`, export/import and exception-directory accessors |
| Pattern and scanning | `Pattern::parse`, `Scanner::scan`, `Scanner::find_first`, xref helpers |
| Resolution | `AddressCursor` fluent operations and `tessera::resolve::*` pipe adapters |
| Runtime modification | `Patch`, `PatchTransaction`, `DiskPatchTransaction`, `PeDiskPatcher`, `Hook<Fn>`, `VTableHook`, `IatHook` |
| Reflection and discovery | `TypeRegistry`, `RttiCatalog`, `BinaryExplorer`, `ObjectView`, `PythonBridgeScanner` |
| Persistence | `ProfileManager`, `JsonProfileStore`, `TargetProfile`, `AddressResolver`, `DiscoverySession` |

PE image parsing accepts both mapped process memory and raw file bytes. The two paths share bounded private readers; their translation-unit layout is an implementation detail and does not change the public `PeImage` API.

Python bridge discovery reports runtime/framework evidence separately from deployment certainty. C-API table presence alone does not imply a statically embedded runtime; use `PythonEnvironmentInfo::deployment` and `framework` independently.

## Safety and component boundaries

- Native inline-hook attach/detach, unwind, thread-coordination, and callback-lifetime obligations are defined in [ADR 0002](adr/0002-native-inline-hook-safety-contract.md) and the [native inline-hook guide](native-inline-hooks.md).
- The compiled `core` and `profiling` components and Python bridge ownership by `rtti` are documented in [ADR 0003](adr/0003-core-profiling-and-rtti-boundaries.md).
- The independent x86 decoder oracle is test-only (`iced-x86==1.21.0`) and is not part of the public SDK dependency graph. See the [developer workflow](development-workflow.md).


## Related implementation and safety notes

- [Safety and validation boundaries](safety-and-boundaries.md) consolidates JSON/profile ownership, PE raw-versus-mapped parsing, memory-write protection recovery, and the bounded x86/x64 decoder contract.

### Wave 3 scanner and xref additions

- `Scanner::scan_batch(range, patterns, options)` reads each memory chunk once for the full pattern span and returns one `ScanResult` per input pattern in the same order. `max_results` is applied independently to each result. An optional `ScanWorkspace` retains the reusable chunk buffer for single and batch scans.
- `Scanner::scan_streaming` invokes a caller callback as each match is found, does not retain the hit vector, and stops when the callback returns false. `ScanReadPolicy::Strict` reports inaccessible regions and partial reads; the default `BestEffort` policy continues across unreadable pages.
- `xref::find_pointer_refs_batch` scans multiple pointer targets through the batch scanner.
- `xref::find_conditional_branches` resolves near conditional branches (`0F 8x rel32`) to a target.
- `xref::find_decoded_xrefs` performs a strict instruction-boundary linear sweep from `instruction_range.begin`; it classifies direct/conditional branches, RIP-relative data references and indirect x86/x64 CALL/JMP operands. The range must start at a known instruction boundary; undecodable or unreadable bytes fail closed. `xref::find_decoded_xrefs_batch` performs the same sweep once for a span of target addresses and returns one result per input target.
- `xref::find_indirect_refs` verifies x86 absolute and x64 RIP-relative indirect CALL/JMP slots by decoding the instruction and dereferencing the pointer operand. `PeImage::relocations()` exposes bounds-checked base relocation entries, and `xref::find_relocated_pointer_refs` resolves HIGHLOW/DIR64 data pointers using the loaded module base.
- `AddressCursor` exposes bounded instruction stepping, call/RIP-relative instruction discovery, operand-target resolution, and cycle/hop-limited thunk following. These operations use the internal shared decoder and return errors for unsupported or unreadable instructions.



## Resolution diagnostics

`ResolutionTrace` can be passed to the additive `AddressResolver::resolve_entry` overload to record the resolution stage and terminal status without changing the target-profile JSON schema.


## Offline PE and file patching

PeFileBackend adapts raw PE file bytes to the read-only IMemoryBackend contract. Existing MemoryReader, Scanner, xref and RTTI tooling can inspect file-backed headers and section data without loading or executing the image. Unmapped RVAs return bounded errors. DiskPatchTransaction separately stages file-offset edits, checks optional expected bytes, validates the rebuilt PE, supports a backup, recalculates the Optional Header checksum, and requires explicit opt-in before invalidating an Authenticode signature.

PeDiskPatcher::find_code_caves reports eligible runs in section alignment padding; it does not allocate or write those areas.

## Hook and memory analysis helpers

VTableHook owns a per-object shadow-vftable copy and atomically swaps/restores that object's vptr. The caller must supply a valid bounded slot count, set all shadow slots before installation, and keep the object and target functions alive. IatHook changes one named import slot in an already mapped module with page-protection restoration and rollback handling. read_scatter coalesces nearby reads while preserving input result order; MemorySnapshot::capture and diff report contiguous changed byte ranges.

## Optional command-line tooling

The offline analysis CLI is outside the core SDK and is disabled by default. Enable it with -DTESSERA_BUILD_CLI=ON (and keep TESSERA_BUILD_TARGETS=ON) to build tessera inspect, scan, rtti, profile verify/diff, and export-symbols --format json. No third-party C++ dependency is introduced.
