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
