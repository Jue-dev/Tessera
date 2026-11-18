# ADR 0001: Initial Modular C++23 Architecture

- **Status**: Accepted
- **Context**: Legacy single-header memory utilities couple Win32 headers (`Windows.h`), exception handling, untyped `uintptr_t` addresses, and ad-hoc pattern scanning into a single translation unit.
- **Decision**:
  1. Partition Tessera into strict layers (L0 `core` through L3 `targets`) exported as granular CMake static library targets (`tessera::core`, `tessera::memory`, ..., `tessera::tessera`).
  2. Enforce zero `<Windows.h>` leakage in public headers via an automated header self-containment test.
  3. Standardize on `Result<T>` (`std::expected<T, Error>`) for all fallible operations.
  4. Introduce `IMemoryBackend` so all L1–L3 components (`MemoryReader`, `MemoryWriter`, `Scanner`, `PeImage`, `AddressCursor`, `Patch`, `AddressResolver`) can be deterministically unit-tested against `FakeMemoryBackend` without requiring a live target process.
  5. Enforce fail-closed verification (`VerifiedAddress`) before any cached or fallback-resolved address is consumed by `Patch` or `Hook`.
