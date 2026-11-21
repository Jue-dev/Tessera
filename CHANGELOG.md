# Changelog

All notable changes to Tessera are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Read-only raw-PE PeFileBackend, transactional disk patching with checksum/signature safeguards, and alignment-padding code-cave discovery.
- Additive VTableHook and IatHook RAII adapters, coalesced scatter reads, and memory snapshot/diff helpers.
- OFF-by-default TESSERA_BUILD_CLI with offline PE inspection, scanning, RTTI, profile verification/diff, and JSON symbol export.
- Shared internal x86/x64 instruction decoder in `src/disasm/`, reused by scanner, resolver, and native-hook relocation paths.
- Pattern metadata and exact-byte anchor filtering for masked scans, plus multi-pattern `scan_batch` support.
- Decoder-assisted hybrid cross-reference discovery, including x86 PE relocation-aware references.
- Semantic `AddressCursor` stepping and structured `resolution_trace` diagnostics for target resolution.
- Fuzz coverage for pattern, PE, JSON, profile JSON, Python bridge, scanner, RTTI discovery, and native-hook inputs.
- Deterministic PE32/PE32+ fixtures, Windows backend mock validation, and installed-SDK consumer coverage.
- JSON benchmark output and validation support for reproducible scanner throughput comparisons.

### Changed
- Consolidated GitHub Actions into CI, quality, fuzz, and release lifecycle workflows, with five shared task-oriented scripts.
- Consolidated safety notes and removed superseded historical native-hook documents; updated build, API, architecture, fuzz, and platform guides.
- Internal decoder ownership remains below the public API; no public disassembler surface is introduced.
- SDK packaging and CMake package exports support installed consumers and architecture/configuration-specific libraries.
- CI validation includes x86/x64 builds, shuffled tests, decoder differential checks, coverage, sanitizers, CodeQL, and clang-tidy.

### Security
- Added CodeQL analysis and sanitizer-backed validation paths, including ThreadSanitizer and AddressSanitizer/UndefinedBehaviorSanitizer configurations.
- Documented security policy and vulnerability reporting guidance.
