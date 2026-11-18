# Tessera Architecture (C++23)

Tessera is a modular C++23 static library SDK for Windows process, memory, binary analysis, runtime patching/hooking, and target profile management.

## Layering Hierarchy (L0 – L3)

- **L0 (`core`)**: Zero-dependency foundation (`Address`, `Rva`, `AddressRange`, `ProcessId`, `Error`, `Result<T>`, `Status`, pipe `|` composition, `checked_math`, `FunctionRef`, `enum_flags`, `TESSERA_ASSERT`).
- **L0.5 (`diagnostics`, `reflection`)**: Lightweight observability (`DiagnosticObserver`, `describe(Error)`) and compiler-RTTI-independent type metadata (`TypeRegistry`, `TypeInfo`, `FieldInfo`, `BaseClassInfo`, `MethodInfo`, `EnumInfo`, `TypeBuilder<T>`, `DynamicTypeBuilder`, `EnumBuilder<E>`).
- **L1 (Process/Memory-independent)**:
  - `pattern`: Compile-time `_sig` literal and runtime byte pattern matching.
  - `utility`: `scope_guard`, string manipulation, SHA-256 (`bytes`), hex encoding, strict UTF-8/UTF-16 conversion, Windows path normalization.
  - `filesystem`: Atomic file writing (`AtomicFileWriter`), advisory file locking (`FileLock`), whole-file reading.
  - `json`: Strict RFC 8259 DOM parser and serializer (`int64`, `uint64`, `double` preservation).
  - `logging`: Structured multi-sink logger (`ConsoleSink`, `DebuggerSink`, `FileSink`, `MemorySink`).
  - `profiling`: High-resolution `Stopwatch`, `ScopeTimer`, and `run_benchmark`.
- **L1 (Process/Memory)**:
  - `process`: Process enumeration, lifecycle, architecture inspection (`IsWow64Process2`), and opaque Win32 handle boundary (`platform/windows/native.hpp`).
  - `memory`: `IMemoryBackend`, `WindowsMemoryBackend`, `MemoryReader`, transactional `MemoryWriter` (2-pass validation & rollback), `ProtectionScope`, and `ProcessAddress` (`tessera::local` fast-path).
- **L2 (Binary Analysis & Runtime Operations)**:
  - `scanner`: Multi-region signature scanning (`Scanner`) with chunk boundary overlap (`pattern.size() - 1`) and `xref` discovery.
  - `module`: `ModuleCatalog` snapshots and bounded `PeImage` parsing (exports, imports, `.pdata` exception functions, CodeView RSDS).
  - `resolver`: Dual-ergonomics address resolution (`AddressCursor` dot-chaining and `resolve::*` pipe adapters).
  - `rtti`:
    - `RttiCatalog`: MSVC PE32 (x86) and PE32+ (x64) `CompleteObjectLocator`, `TypeDescriptor`, `ClassHierarchyDescriptor`, `BaseClassDescriptor`, `vftable` discovery, instance identification, and PMD-based `cast_to`.
    - `BinaryExplorer`: Blind/exploratory discovery of non-virtual `.?AU`/`.?AV`/`.?AW4` types, `.pdata` + `E8` call graphs, strings + xrefs, `[rcx/ecx + disp]` struct reconstruction, live instance finding, and ReClass-style memory dissection.
    - `PythonBridgeScanner`: C++/Python bridge discovery for both external `pythonXX.dll` and statically-embedded `.exe` Python (`PythonDeployment::StaticEmbedded`), extracting `_inittab`, `PyMethodDef`, `PyMemberDef`, `PyGetSetDef`, `PyTypeObject`, and xref-linked module names.
    - `ObjectView`: Unified runtime inspection/mutation of virtual, non-virtual, and Python-exposed C++ objects.
  - `patch`: Single-patch and multi-patch transactional memory modifications (`Patch`, `PatchTransaction`).
  - `hook`: Type-safe inline function hooking (`Hook<Fn>`) with process-wide critical section serialization.
  - `profile`: Versioned application settings (`SettingsSchema`, `Profile`, `ProfileManager`, `JsonProfileStore`, `ISecretStore`).
- **L3 (`targets`)**:
  - `target_profiles`: Pure data model (`TargetProfile`, `TargetBuild`, `AddressEntry`, `ResolutionRecipe` including `RttiVTable`, `StringXref`, and `PythonMethod`).
  - `target_profiles_json`: JSON schema serialization and migration.
  - `target_runtime`: Live process fingerprinting (`TargetFingerprinter`), verified address resolution (`AddressResolver`, `VerifiedAddress`), and `DiscoverySession`.
