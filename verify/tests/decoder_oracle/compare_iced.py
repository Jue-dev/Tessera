#!/usr/bin/env python3
"""Compare Tessera's accepted instruction boundaries with pinned iced-x86."""

from __future__ import annotations

import random
import subprocess
import sys

from iced_x86 import Decoder


def build_cases() -> list[tuple[int, bytes]]:
    rng = random.Random(0x7E55E2A)
    cases: list[tuple[int, bytes]] = []

    def add(bitness: int, data: bytes) -> None:
        if 0 < len(data) <= 15:
            cases.append((bitness, data))

    # Curated common instructions and prefix/addressing families.
    curated = [
        b"\x90", b"\xC3", b"\x55", b"\x48\x89\xE5",
        b"\x48\x8B\x05\x10\x00\x00\x00",
        b"\xE8\x01\x00\x00\x00", b"\xEB\x02",
        b"\x0F\x85\x01\x00\x00\x00",
        b"\xC5\xF8\x58\xC0", b"\xC4\xE1\x78\x58\xC0",
        b"\x62\xF1\x7C\x48\x58\xC0",
        b"\x67\x8B\x44\x8D\x10", b"\x66\xB8\x34\x12",
        b"\xF3\x0F\x1E\xFA", b"\x0F\x1F\x44\x00\x00",
    ]
    for bitness in (32, 64):
        mode = "x86" if bitness == 32 else "x64"
        for data in curated:
            add(bitness, data)

        # Every primary opcode with deterministic trailing bytes.
        for opcode in range(256):
            add(bitness, bytes([opcode]) + bytes(rng.randrange(256) for _ in range(14)))
        # Two-byte map and escaped 0F 38 / 0F 3A maps.
        for opcode in range(256):
            tail = bytes(rng.randrange(256) for _ in range(13))
            add(bitness, b"\x0F" + bytes([opcode]) + tail)
            add(bitness, b"\x0F\x38" + bytes([opcode]) + tail[:12])
            add(bitness, b"\x0F\x3A" + bytes([opcode]) + tail[:12])

        # Exercise ModRM values for representative one- and two-byte forms.
        for opcode in (0x8B, 0x89, 0x8D, 0xC7, 0xFF, 0xF7, 0xD1):
            for modrm in range(256):
                add(bitness, bytes([opcode, modrm]) + bytes(rng.randrange(256) for _ in range(8)))
        for opcode in (0xB6, 0xB7, 0xAF, 0x1F, 0x58):
            for modrm in range(256):
                add(bitness, b"\x0F" + bytes([opcode, modrm]) +
                    bytes(rng.randrange(256) for _ in range(8)))

        # Deterministic random streams catch combinations not covered above.
        for _ in range(2500):
            length = rng.randint(1, 15)
            add(bitness, bytes(rng.randrange(256) for _ in range(length)))

    return cases


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: compare_iced.py <decoder-probe>", file=sys.stderr)
        return 2

    cases = build_cases()
    payload = "".join(
        ("x86" if bitness == 32 else "x64") + " " +
        " ".join(f"{byte:02X}" for byte in data) + "\n"
        for bitness, data in cases
    )
    result = subprocess.run(
        [sys.argv[1]], input=payload, text=True, capture_output=True, check=True
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(cases):
        print(f"probe returned {len(lines)} results for {len(cases)} inputs", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1

    compared = 0
    mismatches = []
    for (bitness, data), line in zip(cases, lines, strict=True):
        parts = line.split()
        if len(parts) != 2:
            mismatches.append((bitness, data, "malformed probe output", line))
            continue
        tessera_accepts, tessera_length = int(parts[0]), int(parts[1])
        if not tessera_accepts:
            continue

        oracle = Decoder(bitness, data, ip=0x10000000).decode()
        if oracle.is_invalid:
            # Tessera documents a bounded length decoder rather than a complete
            # semantic validator; invalid oracle encodings are not a length oracle.
            continue

        compared += 1
        if tessera_length != oracle.len:
            mismatches.append((bitness, data, tessera_length, oracle.len))

    print(f"decoder differential: {compared} valid accepted encodings compared "
          f"across {len(cases)} deterministic inputs")
    if compared < 500:
        print("too few valid overlap cases; oracle corpus did not exercise enough of the decoder",
              file=sys.stderr)
        return 1
    if mismatches:
        for bitness, data, actual, expected in mismatches[:25]:
            print(f"mode={bitness} bytes={data.hex(' ')} tessera={actual} iced={expected}",
                  file=sys.stderr)
        print(f"{len(mismatches)} instruction-boundary mismatch(es)", file=sys.stderr)
        return 1
    print("decoder differential: PASS (0 boundary mismatches)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
