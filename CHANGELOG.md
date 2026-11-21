# Changelog

All notable changes to Tessera are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning once stable releases begin.

## [Unreleased]

### Added
- Shared internal x86/x64 instruction decoder used by hook, scanner and resolver without exposing a public disassembler API.
- Pattern scanning acceleration with SSE2 and AVX2 SIMD dispatch, including the forced-scalar validation path.
- Single-pass multi-pattern scanning through `Scanner::scan_batch`, retaining per-pattern result limits and chunk overlap semantics.
- Decoder-assisted hybrid cross-reference discovery, xref-kind classification, batched pointer-reference scanning and x86 PE `.reloc` pointer cross-references.
- Semantic `AddressCursor` instruction stepping, operand resolution, call/RIP-relative navigation and thunk-chain traversal.
- Target-resolution diagnostics through `resolution_trace`, including fallback, validation and session-cache outcomes.
- Eight fuzz targets covering pattern, PE, JSON, profile JSON, Python bridge, scanner, RTTI discovery and native-hook inputs.
- Dedicated validation for TSan, ASan/UBSan, line/branch coverage, CodeQL and clang-tidy.
- Machine-readable `--json` benchmark output and validation tooling for repeatable throughput comparisons.
- CMake package exports, installed SDK layouts and standalone installed-consumer coverage.

### Changed
- Scanner and xref pipelines share bounded memory reads, chunk overlap handling, region filtering and cancellation semantics.
- Target resolution combines build fingerprints, primary/fallback recipes, validation rules and verified session caching.
- Release packaging validates the x86/x64 Debug/Release SDK layouts and publishes checksummed archives.

### Fixed
- Checked address arithmetic and architecture-specific decoding guard x86/x64 boundary cases in scanning and reference resolution.
- Failed or stale target resolutions remain distinguishable from verified addresses, while cache invalidation prevents reuse after module changes.
- Pattern candidate filtering rejects non-matching anchors before full masked comparisons.
