# Changelog

All notable changes to Tessera are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning once stable releases begin.

## [Unreleased]

### Added
- Private shared x86/x64 instruction decoder layer for hook, scanner and resolver internals.
- Pattern metadata for leading/trailing wildcards and a secondary full-byte anchor filter.
- Security policy and vulnerability reporting guidance.

### Changed
- Internal decoder ownership is below hook, scanner and resolver; no public disassembler API is exposed.

### Fixed
- Pattern search rejects candidates efficiently with a second exact-byte anchor before full masked comparison.
