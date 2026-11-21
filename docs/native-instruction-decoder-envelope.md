# Native x86/x64 decoder and relocation envelope

This document inventories the bounded instruction-length metadata decoder used by the native inline-hook prologue analyzer. It is a maintenance boundary, **not** a claim that Tessera implements a complete x86/x64 disassembler or validates every architectural encoding.

Implementation: `src/hook/backends/x86_instruction_decoder.cpp` and `x86_instruction_decoder.hpp`.

## Decoder contract

- Modes: 32-bit x86 and 64-bit x86-64.
- Maximum instruction length: 15 bytes. Every read is bounded by both the supplied byte span and that architectural limit.
- Output: instruction length, opcode metadata, ModRM.reg, relative-operand offset/width, and RIP-relative displacement offset.
- The decoder does not execute instructions, validate CPU feature availability, or prove that an opcode is semantically valid on every processor generation.
- Successful length decoding is only the first gate. The relocator separately rejects branch and displacement layouts it cannot preserve.

## Encoding families represented

| Family | Length/address metadata handled | Mode notes and limits |
|---|---|---|
| Legacy prefixes | LOCK, REP/REPNZ, segment overrides, operand-size override, address-size override | Prefixes count toward the 15-byte bound. A legacy prefix after a REX prefix makes the earlier REX ineffective. |
| REX | x64 REX.W/R/X/B prefix byte handling | Not recognized as REX in x86 mode. |
| One-byte opcode map | Selected arithmetic/logic, move, stack, string, control-flow, I/O, flag, and system instruction forms; immediate and ModRM forms | Explicit mode checks reject legacy segment/decimal-adjust forms unavailable in long mode. Unsupported one-byte opcodes fail closed. |
| 0F map | Selected no-ModRM forms, ModRM forms, immediate-byte forms, and near conditional branches 0F 80–8F | 0F 38 and 0F 3A escape maps are recognized separately. This is a bounded length table, not a semantic validator for the entire map. |
| 0F 38 / 0F 3A | ModRM and displacement structure; 0F 3A additionally accounts for an immediate byte | Unknown/reserved semantic combinations are not guaranteed to be rejected solely by length decoding. |
| VEX | Two-byte C5 and three-byte C4 prefixes; maps 1, 2, and 3 | Vector forms reject legacy LOCK/REP/66 and REX prefix combinations. Unsupported maps are rejected. |
| EVEX | Four-byte 62 prefix; maps 1, 2, and 3 | Reserved prefix-bit patterns are rejected. Vector opcode length metadata is handled without executing the instruction. |
| ModRM/SIB and displacement | ModRM register/memory modes, SIB, disp8, disp32, x86 address-size-override disp16, x64 RIP-relative disp32 | RIP-relative metadata is emitted only for the x64 no-SIB mod=00/rm=101 form without address-size override. |
| Immediate/relative fields | Byte, operand-sized, address-sized, MOV-register immediate, far pointer, ENTER, rel8, rel16/rel32 metadata | Decoder metadata does not imply the relocator supports every decoded relative width. |

## Explicit rejection boundaries

The current implementation explicitly rejects:

- Null/empty input, truncated prefixes/opcodes/ModRM/SIB/displacements/immediates, and any instruction extending beyond 15 bytes.
- One-byte opcodes not represented by the bounded table.
- AMD XOP encodings selected by the 8F map selector; XOP is outside the supported envelope.
- Reserved two-byte opcodes 0F 0A and 0F 0C.
- The ambiguous operand-size-prefixed 66 0F 78 / 66 0F 79 SSE4a forms.
- VEX/EVEX map selectors outside 1, 2, and 3, malformed EVEX reserved-bit combinations, and vector encodings combined with disallowed legacy/REX prefixes.
- Selected invalid ModRM group encodings (including unsupported 8F and FE group selectors), memory-form ModRM for control/debug-register MOV opcodes 0F 20–23 (these require register-direct ModRM), and long-mode-invalid legacy forms.

The reject list above describes explicit guards in this implementation; it is not an exhaustive catalogue of every architecturally reserved opcode encoding.

## Additional relocation constraints

The relocator applies stricter rules than the decoder:

- Short JMP and short conditional branches are expanded to rel32 forms.
- LOOP/LOOPE/LOOPNE/JCXZ-family short branches use explicit branch stubs to preserve counter and flag behavior.
- Relative operands that require relocation must be supported by the relocation path; rel16 CALL/JMP forms are rejected rather than guessed.
- Branches into the middle of a displaced instruction are rejected. Internal branches to exact displaced instruction boundaries are remapped to the corresponding trampoline instruction.
- x64 RIP-relative memory references into the overwritten prologue are rejected; external RIP-relative targets must remain within signed rel32 reach from the trampoline.
- PC-materialization patterns such as CALL-next are rejected when the relocator cannot preserve their original address-observation semantics.

## Regression evidence

- Decoder boundary tables cover legacy/REX prefixes, ModRM/SIB, displacement/immediate widths, relative fields, RIP-relative fields, truncation, and the 15-byte limit (PR #31).
- Negative boundary tests cover reserved 0F opcodes, XOP, ambiguous SSE4a forms, unsupported VEX map selection, LOCK-prefixed vector forms, and mode-specific legacy opcodes (PR #36).
- Relocation integration tests execute representative relocated RIP-relative, short/near branch, LOOP-family, and internal-branch cases, and verify restoration of original bytes.
- Fuzz campaigns exercise decoding/relocation setup. Arbitrary fuzz-generated trampoline bytes are not executed.

## Known validation gap

The repository now includes an independent, test-only decoder differential oracle: `verify/tests/decoder_oracle/decoder_probe.cpp` is compared against pinned `iced-x86==1.21.0` by `verify/tests/decoder_oracle/compare_iced.py` in the `Independent Decoder Differential (iced-x86)` CI job. The dependency is not part of the public SDK/runtime ABI. This provides independent boundary comparisons for the oracle's test corpus, but it is not an exhaustive proof that every x86/x64 encoding is supported or semantically validated.
