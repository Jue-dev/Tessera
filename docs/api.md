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
| Process and memory | `Process`, `IMemoryBackend`, `MemoryReader`, `MemoryWriter`, `ProtectionScope` |
| PE/module inspection | `PeImage::from_memory`, `PeImage::from_raw_bytes`, `PeImage::from_file`, export/import and exception-directory accessors |
| Pattern and scanning | `Pattern::parse`, `Scanner::scan`, `Scanner::find_first`, xref helpers |
| Resolution | `AddressCursor` fluent operations and `tessera::resolve::*` pipe adapters |
| Runtime modification | `Patch`, `PatchTransaction`, `Hook<Fn>` |
| Reflection and discovery | `TypeRegistry`, `RttiCatalog`, `BinaryExplorer`, `ObjectView`, `PythonBridgeScanner` |
| Persistence | `ProfileManager`, `JsonProfileStore`, `TargetProfile`, `AddressResolver`, `DiscoverySession` |

PE image parsing accepts both mapped process memory and raw file bytes. The two paths share bounded private readers; their translation-unit layout is an implementation detail and does not change the public `PeImage` API.

Python bridge discovery reports runtime/framework evidence separately from deployment certainty. C-API table presence alone does not imply a statically embedded runtime; use `PythonEnvironmentInfo::deployment` and `framework` independently.

## Safety and component boundaries

- Native inline-hook attach/detach, unwind, thread-coordination, and callback-lifetime obligations are defined in [ADR 0002](adr/0002-native-inline-hook-safety-contract.md) and the [native inline-hook guide](native-inline-hooks.md).
- The compiled `core` and `profiling` components and Python bridge ownership by `rtti` are documented in [ADR 0003](adr/0003-core-profiling-and-rtti-boundaries.md).
- The independent x86 decoder oracle is test-only (`iced-x86==1.21.0`) and is not part of the public SDK dependency graph. See the [developer workflow](development.md).


## Related implementation and safety notes

- [JSON validation boundaries](json-validation-boundaries.md) explains the separate profile and target-profile wire-format ownership.
- [Memory write recovery](memory-write-recovery.md) documents explicit retry ownership for pending page-protection restoration.
- [Native decoder envelope](native-instruction-decoder-envelope.md) defines the supported bounded decoder metadata and relocation rejection rules.
