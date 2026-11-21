# Safety and validation boundaries

This document consolidates the former JSON validation, memory-write recovery, and native instruction decoder notes. It records implementation constraints and validation evidence; it is not a claim of universal binary or execution safety.

## JSON validation and ownership

Profile and target-profile persistence use the shared JSON DOM and parser. The parser owns RFC 8259 syntax, UTF-8 validity, nesting limits, duplicate-key policy, and input-size limits. Both persistence paths use the shared UTF-8 filesystem reader and atomic file writer.

Profile JSON owns SettingValue conversion, settings normalization, renamed/deprecated keys, secret references, and ISecretStore interactions. Arrays in settings mean StringList; unsupported kinds are rejected with profile-specific errors.

Target-profile JSON owns target enums, resolution recipes, validation rules, module/build fingerprints, audit records, hexadecimal RVA/fingerprint fields, and structural invariants enforced by validate_target_profile_schema (application identity, executable list, unique build/address IDs, module references, and required validation rules).

These modules do not share a stable field schema, error taxonomy, or normalization policy. Keep their conversions local; a generic field framework would erase useful error context. The common parser/writer and filesystem APIs are the stable boundary.

python_bridge.cpp and discovery.cpp share the private src/rtti/readable_chunks.hpp traversal helper. It owns only mechanics (readable-region queries, clipping, overlapped chunk reads, and executable-protection reporting); Python and MSVC RTTI consumers keep their own interpretation and validation.

## PE parser policy

pe_image_detail.hpp owns private ImageSource adapters shared by pe_image_memory.cpp and pe_image_raw.cpp. Their policies intentionally differ: mapped images use process-address reads and a bounded e_lfanew policy, while raw files additionally validate section raw offsets/sizes against file length and translate RVAs through raw section ranges. Keep raw-file bounds explicit when refactoring; do not hide them behind a permissive shared reader.

## Memory write protection recovery

MemoryWriter::write_with_report performs a validated write and reports partial-transfer, rollback, instruction-cache, and page-protection outcomes.

When temporary page-protection restoration fails, WriteReport retains a PendingProtectionRestore containing the exact shared Process state, affected range, and previous protection returned by the successful protection change. The report is not successful while a protection warning remains. Retry with MemoryWriter::restore_pending_protections(report); only successfully restored tickets are removed. Failed tickets remain available with their original range/protection pair.

The rollback path reuses an existing ticket when the first write pass could not restore a page. It must not mistake temporary elevated protection for the original protection or create a second ticket that could later re-elevate the page.

Patch retains the WriteReport when apply/restore leaves pending protection tickets. A later Patch::restore() or destructor cleanup retries those tickets before byte restoration. MemoryWriter::write returns only Status, so it performs one immediate retry for a transient restoration failure; callers needing explicit retry ownership and inspection must use write_with_report.

Failure policy:
- Never report success while a protection restoration is pending.
- Never reconstruct original protection from a later query; use only the value returned by the successful protection change.
- Do not discard a WriteReport with pending tickets when the caller needs to retry restoration.
- A failed rollback write remains a rollback error even if protection restoration is later recovered.
- Keep the restoration ticket scoped to the exact backend slice. Do not widen, merge, or reconstruct it.
- Serialize overlapping writes or temporary protection changes at page level where required; tickets are operation-owned and do not coordinate overlapping concurrent scopes.

## Native x86/x64 decoder and relocation envelope

The native inline-hook decoder is a bounded instruction-length metadata decoder, not a complete x86/x64 disassembler or semantic validator for every architectural encoding. Implementation is in src/hook/backends/x86_instruction_decoder.cpp and its private header.

Contract:
- Modes: x86 and x86-64; maximum instruction length is 15 bytes.
- Output includes instruction length, opcode metadata, ModRM.reg, relative operand offset/width, and RIP-relative displacement offset.
- The decoder does not execute instructions, validate CPU feature availability, or prove processor-generation semantics.
- Length decoding is only the first gate; relocation separately rejects layouts it cannot preserve.

Represented families include legacy prefixes, x64 REX, selected one-byte and 0F opcode maps, 0F 38/3A maps, VEX and EVEX maps 1–3, ModRM/SIB and displacement forms, and byte/operand/address-sized immediate and relative fields. Unsupported or malformed encodings fail closed; the table is deliberately bounded.

Explicit rejection guards include null/empty and truncated instructions, input crossing the 15-byte limit, one-byte opcodes outside the table, AMD XOP, reserved 0F 0A/0C, ambiguous operand-size-prefixed 66 0F 78/79 forms, unsupported VEX/EVEX map selectors, malformed EVEX reserved bits, disallowed vector/legacy prefix combinations, selected invalid ModRM groups, invalid register-only control/debug-register MOV forms, and selected long-mode-invalid legacy forms. This is not an exhaustive catalogue of every architecturally reserved encoding.

Relocation imposes stricter constraints:
- Short JMP and short conditional branches are expanded to rel32 forms.
- LOOP/LOOPE/LOOPNE/JCXZ-family branches use explicit stubs that preserve counter and flag semantics.
- Unsupported relative widths (including rel16 CALL/JMP) are rejected.
- Branches into the middle of displaced instructions are rejected; exact internal instruction-boundary targets are remapped.
- x64 RIP-relative memory references into the overwritten prologue are rejected; external targets must remain within signed rel32 reach.
- CALL-next PC-materialization patterns are rejected when original address-observation semantics cannot be preserved.

The independent iced-x86 1.21.0 decoder oracle is test-only, not a runtime or SDK dependency. It compares the configured regression corpus and is not exhaustive proof of every encoding. Regression suites and fuzz harnesses cover decoder boundaries, relocation setup, malformed inputs, and lifecycle paths.

## Native inline-hook operational boundary

Native inline hooks support the documented x86/x64 implementation and rely on host-side quiescence/admission control. A finite thread snapshot does not cover threads created afterward. Strict, best-effort, and no-suspension policies have distinct guarantees. Hook::acquire() pins callable lifetime for leased invocations, but original() is a raw non-owning pointer.

The process-wide transaction mutex does not make the active-hook registry shared across independently loaded Tessera backend images. The supported deployment boundary remains one loaded Tessera native-hook backend image per process. See docs/adr/0002-native-inline-hook-safety-contract.md for the authoritative contract.
