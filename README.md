# Tessera (C++23 Modular Windows Memory, RTTI, Non-Virtual Reflection & Python Bridge SDK)

**Tessera**; modern C++23 (`MSVC 19.38+` / `Clang-CL 18+`) ile geliştirilmiş, sıfır `<Windows.h>` başlık sızıntısı garantili, yüksek performanslı bir Windows bellek analizi, **Virtual & Non-Virtual RTTI/Reflection**, **Kör Keşif (Blind Discovery)** ve **C++/Python (DLL & Statik Gömülü `.exe`) Köprü Keşif** SDK'sıdır.

---

## Temel Özellikler

- **Katmanlı Modüler Mimari (L0 – L3):**
  - **L0 (`tessera::core`):** `Address`, `Rva`, `AddressRange`, `Result<T>`, `Status`, taşma korumalı aritmetik (`checked_math`), `FunctionRef`.
  - **L0.5 (`tessera::diagnostics`, `tessera::reflection`):** Derleyici RTTI'sinden (`/GR-`) bağımsız tip şeması (`FieldInfo`, `BaseClassInfo`, `MethodInfo`, `EnumInfo`, `TypeBuilder<T>`, `DynamicTypeBuilder`, `EnumBuilder<E>`, `TypeRegistry`).
  - **L1 (`tessera::pattern`, `tessera::utility`, `tessera::filesystem`, `tessera::json`, `tessera::logging`, `tessera::profiling`, `tessera::process`, `tessera::memory`):** Derleme zamanı `operator""_sig` (`consteval`) imza derleyicisi, RFC 8259 JSON ayrıştırıcısı, atomik dosya yazıcı ve `IMemoryBackend` soyutlaması.
  - **L2 (`tessera::scanner`, `tessera::module`, `tessera::resolver`, `tessera::rtti`, `tessera::patch`, `tessera::hook`, `tessera::profile`):**
    - **`RttiCatalog`:** PE32 (x86) ve PE32+ (x64) MSVC `CompleteObjectLocator`, `TypeDescriptor`, `ClassHierarchyDescriptor`, çoklu/sanal kalıtım (`PMD`) ve `vftable` keşfi.
    - **`BinaryExplorer` (Kör Keşif Motoru):** Vtable'sız non-virtual `.?AU`/`.?AV`/`.?AW4` taraması, `.pdata` + `E8` fonksiyon kataloğu, string + xref haritası, `[rcx/ecx + disp]` komutlarından otomatik `struct` alan çıkarımı (`reconstruct_struct`), canlı örnek taraması (`find_instances`) ve ReClass tarzı bellek diseksiyonu (`dissect_memory`).
    - **`PythonBridgeScanner` (DLL & Statik Gömülü `.exe` Python Keşfi):** Harici `pythonXX.dll` olmasa bile doğrudan `.exe` içine statik gömülmüş (`PythonDeployment::StaticEmbedded`) CPython/PyBind11/Boost.Python/Cython yapılarını, `_inittab`, `PyMethodDef`, `PyMemberDef`, `PyGetSetDef` tablolarını ve `.text` xref'leri üzerinden modül adlarını otomatik çıkarır.
    - **`ObjectView`:** Hem virtual hem non-virtual C++ nesnelerinin alanlarını, bitfield'larını, taban alt-nesnelerini ve metotlarını okuma/yazma/çözümleme.
  - **L3 (`tessera::targets`):** `Rva`, `Export`, `Pattern`, `Relative`, `PointerChain`, `Field`, `RttiVTable`, `StringXref` ve `PythonMethod` stratejileriyle çoklu-derleme (multi-build) hedef doğrulama ve kalıcılık.

---

## Hızlı Başlangıç (Derleme, Test, Paketleme ve Temizlik)

```powershell
# 1. x64-debug yapılandırması, derleme (tek parça tessera.lib + 6 örnek + testler) ve test koşumu
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure

# 2. Diğer projelere aktarım için hazır SDK paketini (dist/TesseraSDK + Tessera.props) oluşturma
.\scripts\export_sdk.ps1

# 3. Gereksiz derleme/IDE/geçici dosyaları temizleme (-DryRun ile silmeden önizleme)
.\scripts\clean.ps1 -DryRun
.\scripts\clean.ps1
```

## Diğer Projelere Aktarım

- **Visual Studio (`.sln` / `.vcxproj`):** `.\scripts\export_sdk.ps1` çalıştırdıktan sonra oluşan `dist/TesseraSDK/Tessera.props` dosyasını Visual Studio *Property Manager -> Add Existing Property Sheet* ile projenize ekleyin; `include/` yolu ve tek parça `tessera.lib` otomatik bağlanır.
- **CMake (`find_package`):**
  ```cmake
  list(APPEND CMAKE_PREFIX_PATH "C:/path/to/Tessera/dist/TesseraSDK/x64/Release")
  find_package(Tessera CONFIG REQUIRED)
  target_link_libraries(BenimProjem PRIVATE tessera::tessera)
  ```

---

## Örnek Uygulamalar (`examples/`)

1. `tessera_example_01_scan_and_pe` (`basic_scan_and_resolve.cpp`): Süreç, PE bölümleri/export/import/`.pdata`, `_sig` tarama ve `AddressCursor`.
2. `tessera_example_02_patch_and_hook` (`memory_patch_and_hook.cpp`): Bellek okuma/yazma, `Patch::nop`/`Patch::bytes`, `PatchTransaction` ve `Hook<Fn>`.
3. `tessera_example_03_rtti_and_reflection` (`rtti_and_object_view.cpp`): Virtual & Non-Virtual reflection, bitfield, `ObjectView` ve canlı `RttiCatalog`.
4. `tessera_example_04_blind_discovery` (`blind_binary_discovery.cpp`): Kör keşif (`BinaryExplorer`), string/xref, `[rcx + disp]` struct çıkarımı ve ReClass tarzı `dissect_memory`.
5. `tessera_example_05_python_bridge` (`python_bridge_discovery.cpp`): DLL olmadan statik gömülü (`StaticEmbedded`) C++/Python köprü keşfi (`PyMethodDef`, `PyMemberDef`).
6. `tessera_example_06_profiles_and_targets` (`profiles_and_targets_workflow.cpp`): `ProfileManager`, `TargetProfile` (`RttiVTable`, `StringXref`, `PythonMethod`), `Logger` ve `ScopeTimer`.

---

## Fuzz Testleri

Gerçek LLVM libFuzzer koşumları, corpus hazırlığı ve sanitizer seçenekleri için [`verify/fuzz/README.md`](verify/fuzz/README.md) dosyasına bakın.

## Belgeler

- [Mimari Genel Bakış](docs/architecture.md)
- [Derleme ve CMake Seçenekleri](docs/build.md)
- [API Kullanım Kılavuzu](docs/api.md)
- [Geliştirici İş Akışı ve Mimari Kararlar](docs/development-workflow.md)


## Optional CMake validation presets

The repository provides matching configure/build presets for x64 and x86 Debug/Release, plus x64 AddressSanitizer, MSVC static analysis, benchmark, and fuzz-smoke configurations. On Windows with the MSVC developer environment and Ninja available, the optional benchmark and deterministic corpus-replay workflows are:

```powershell
cmake --preset x64-bench
cmake --build --preset x64-bench --parallel
ctest --preset x64-bench --output-on-failure

cmake --preset x64-fuzz-smoke
cmake --build --preset x64-fuzz-smoke --parallel
ctest --preset x64-fuzz-smoke --output-on-failure
.\scripts\run-fuzz-smoke.ps1
```

The five benchmark executables are `tessera_bench` (scanner), `tessera_decoder_bench`, `tessera_pe_bench`, `tessera_json_bench`, and `tessera_rtti_discovery_bench`. The eight fuzz harnesses are `tessera_fuzz_pattern`, `tessera_fuzz_pe`, `tessera_fuzz_json`, `tessera_fuzz_profile_json`, `tessera_fuzz_python_bridge`, `tessera_fuzz_scanner`, `tessera_fuzz_rtti_discovery`, and the Windows-only `tessera_fuzz_native_hook`. The standalone smoke script replays each checked-in corpus through the same `LLVMFuzzerTestOneInput` entry point; it complements, but does not replace, longer coverage-guided campaigns.

The optional `decoder-differential` CI job installs the test-only `iced-x86==1.21.0` Python package and compares the in-house x86 decoder's instruction boundaries against that independent oracle. The dependency is confined to the validation job and is not part of the Tessera runtime or installed SDK.

## Wave 3 development and validation

- `Pattern` exposes derived leading/trailing wildcard metadata and a secondary exact-byte anchor without changing its object layout. Search uses both anchors as a cheap candidate filter before the full byte-mask comparison.
- `Scanner::scan_batch` accepts a span of patterns, reads each process-memory chunk once, preserves input order, and applies an independent `max_results` quota to each pattern. Caller-owned `ScanWorkspace` reuses the chunk buffer across scans; `scan_streaming` delivers matches without retaining the hit vector and supports callback cancellation. `ScanReadPolicy::Strict` fails on inaccessible/partial reads while the default best-effort policy skips them. `xref::find_pointer_refs_batch` reuses it for multiple targets; conditional near branches and x86/x64 indirect CALL/JMP references have dedicated helpers. `find_decoded_xrefs` performs a strict linear sweep from a caller-supplied instruction boundary to reject opcode-looking bytes embedded in immediates. PE32 `.reloc` HIGHLOW and PE32+ DIR64 entries are parsed with bounds checks and can be used by `xref::find_relocated_pointer_refs`.
- `AddressCursor` adds bounded decoder-backed `step_instructions`, `find_next_call`, `find_next_rip_relative`, `resolve_operand_target`, and `resolve_thunk_chain` operations. Unsupported instructions, unreadable bytes, cycles, and hop-limit exhaustion are reported rather than guessed.
- All five benchmark executables accept `--json` and emit machine-readable `name`, `iterations`, `ns_per_op`, and `mb_per_s` metrics. Human-readable output remains the default.
- The fallback test shim accepts `--shuffle`, `--seed N`, `--filter substring`, and `--junit path`. CTest registers a deterministic shuffled pass with seed `20261121`.
- Optional coverage is enabled with `-DTESSERA_ENABLE_COVERAGE=ON` on GCC/Clang. Dedicated CI workflows run Clang ASan+UBSan, TSan, CodeQL, coverage export, and scheduled bounded fuzz campaigns for the eight harnesses.
- The tag-driven SDK release pipeline emits `SHA256SUMS.txt` alongside the Windows SDK bundle. See [SECURITY.md](SECURITY.md) for supported-use boundaries and private vulnerability reporting, and [CHANGELOG.md](CHANGELOG.md) for unreleased changes.

Run the repository-wide validation script from a Windows PowerShell session with MSVC and Ninja available:

```powershell
.\scripts\run-final-validation.ps1 -RunFuzz -RunDecoderOracle
```

The sustained native-hook fuzz campaign requires the corresponding Windows Clang/ASan runtime; Microsoft Detours integration additionally requires a local Detours v4.0.1 checkout supplied with `-DetoursRoot`.

