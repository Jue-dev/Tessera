# Native inline hooks (Windows x86/x64)

Tessera provides a native x86/x64 inline-hook backend alongside optional Microsoft Detours. It uses bounded instruction metadata decoding, rollback-aware writes, trampoline relocation, and runtime unwind handling. Unsupported or unsafe instruction layouts fail closed.

## Basic lifecycle

Create a typed Hook<Fn>, install it, and explicitly inspect remove() when cleanup errors matter. Hook::acquire() holds a lock-backed callable lease while a call is active. original() returns a raw, non-owning trampoline pointer and does not participate in call tracking.

## Host responsibilities

- Stop admission of new callers and drain existing callers where concurrent entry is possible. A finite thread snapshot does not cover threads created after the snapshot.
- Choose ThreadPolicy according to the host's quiescence guarantee. None requires an externally quiescent patch window.
- Keep the detour callback and its module alive until all callbacks and raw trampoline users have drained.
- Call remove() and inspect its result before destruction if backend cleanup can fail.
- Use only one loaded Tessera native-hook backend image per process. The transaction mutex is process-wide, but the active-hook registry is not shared across independent backend images.

## Validation and exclusions

The four lifecycle workflows retain x86/x64 builds, Detours integration, sanitizer-backed windows_mock, decoder-oracle comparison, and bounded fuzz campaigns. See docs/adr/0002-native-inline-hook-safety-contract.md for the authoritative lifecycle and failure contract, and safety-and-boundaries.md for decoder limits.

Tessera does not implement ARM64/WoW64 cross-architecture hosting, process injection or hosting, DLL loader techniques, VEH hooks, hardware breakpoints, or PAGE_GUARD hooks.


The separate `VTableHook` API is a per-object shadow-vftable helper; configure its slots before installation and keep the object/functions alive for the entire hook lifetime.
