#pragma once

// Tessera's private x86/x64 instruction-length decoder.
//
// This decoder is intentionally scoped to native-hook prologue analysis. It
// reports instruction boundaries and the relative operands that the
// relocator must repair; it is not a public disassembler API. Every read is
// bounded by both the caller-supplied span and the architectural 15-byte
// instruction limit. Encodings outside the supported maps are rejected.

#include <cstddef>
#include <cstdint>

namespace tessera::detail::x86 {

enum class Mode : std::uint8_t {
    x86,
    x64,
};

struct DecodedInstruction {
    std::uint8_t length = 0;
    std::uint8_t opcode = 0;
    std::uint8_t opcode2 = 0;
    std::uint8_t modrm_reg = 0;
    std::uint8_t relative_offset = 0;
    std::uint8_t relative_size = 0;
    std::uint8_t rip_displacement_offset = 0;
    bool has_relative_operand = false;
    bool has_rip_relative_operand = false;
};

namespace decoder_detail {

constexpr std::size_t kMaximumInstructionLength = 15;

class Cursor final {
public:
    Cursor(const std::uint8_t* data, std::size_t available) noexcept
        : data_(data), available_(available) {}

    [[nodiscard]] bool peek(std::uint8_t& value) const noexcept {
        if (position_ >= available_ || position_ >= kMaximumInstructionLength) {
            return false;
        }
        value = data_[position_];
        return true;
    }

    [[nodiscard]] bool peek_ahead(std::size_t offset, std::uint8_t& value) const noexcept {
        if (offset > kMaximumInstructionLength ||
            position_ > kMaximumInstructionLength - offset) {
            return false;
        }
        const std::size_t index = position_ + offset;
        if (index >= available_ || index >= kMaximumInstructionLength) {
            return false;
        }
        value = data_[index];
        return true;
    }

    [[nodiscard]] bool read(std::uint8_t& value) noexcept {
        if (!peek(value)) {
            return false;
        }
        ++position_;
        return true;
    }

    [[nodiscard]] bool skip(std::size_t count) noexcept {
        if (position_ > available_ || count > available_ - position_ ||
            position_ > kMaximumInstructionLength ||
            count > kMaximumInstructionLength - position_) {
            return false;
        }
        position_ += count;
        return true;
    }

    [[nodiscard]] std::size_t position() const noexcept {
        return position_;
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t available_ = 0;
    std::size_t position_ = 0;
};

enum class Immediate : std::uint8_t {
    none,
    byte,
    operand,
    address,
    mov_register,
    far_pointer,
    enter,
};

struct Encoding {
    bool valid = true;
    bool modrm = false;
    bool relative = false;
    Immediate immediate = Immediate::none;
};

[[nodiscard]] constexpr bool is_legacy_prefix(std::uint8_t value) noexcept {
    switch (value) {
        case 0xF0:
        case 0xF2:
        case 0xF3:
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] constexpr std::size_t operand_immediate_size(
    Mode mode, bool operand16) noexcept {
    (void)mode;
    return operand16 ? 2u : 4u;
}

[[nodiscard]] constexpr std::size_t address_immediate_size(
    Mode mode, bool address_override) noexcept {
    if (mode == Mode::x64) {
        return address_override ? 4u : 8u;
    }
    return address_override ? 2u : 4u;
}

[[nodiscard]] constexpr bool decode_one_byte_opcode(
    std::uint8_t opcode, Mode mode, Encoding& encoding) noexcept {
    encoding = {};

    if (opcode <= 0x3F) {
        const std::uint8_t form = static_cast<std::uint8_t>(opcode & 0x07u);
        if (form <= 3) {
            encoding.modrm = true;
        } else if (form == 4) {
            encoding.immediate = Immediate::byte;
        } else if (form == 5) {
            encoding.immediate = Immediate::operand;
        } else if (form == 6) {
            // PUSH segment-register encodings are not available in long mode.
            if (mode == Mode::x64) {
                encoding.valid = false;
            }
        } else {
            // POP segment-register / decimal-adjust instructions.
            if (mode == Mode::x64) {
                encoding.valid = false;
            }
        }
        return encoding.valid;
    }

    if (opcode >= 0x40 && opcode <= 0x5F) {
        return true; // INC/DEC (x86) and PUSH/POP GPR.
    }
    if (opcode == 0x60 || opcode == 0x61) {
        encoding.valid = mode == Mode::x86; // PUSHA/POPA.
        return encoding.valid;
    }

    switch (opcode) {
        case 0x62: // BOUND (EVEX is recognized before this table).
            encoding.valid = mode == Mode::x86;
            encoding.modrm = true;
            break;
        case 0x63: // ARPL / MOVSXD.
        case 0x69:
        case 0x6B:
        case 0x80:
        case 0x81:
        case 0x82:
        case 0x83:
        case 0x84:
        case 0x85:
        case 0x86:
        case 0x87:
        case 0x88:
        case 0x89:
        case 0x8A:
        case 0x8B:
        case 0x8C:
        case 0x8D:
        case 0x8E:
        case 0x8F:
        case 0xC0:
        case 0xC1:
        case 0xC4:
        case 0xC5:
        case 0xC6:
        case 0xC7:
        case 0xD0:
        case 0xD1:
        case 0xD2:
        case 0xD3:
        case 0xD8:
        case 0xD9:
        case 0xDA:
        case 0xDB:
        case 0xDC:
        case 0xDD:
        case 0xDE:
        case 0xDF:
        case 0xFE:
        case 0xFF:
            encoding.modrm = true;
            break;

        case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            break;
        case 0x68:
        case 0xA9:
            encoding.immediate = Immediate::operand;
            break;
        case 0x6A:
        case 0xA8:
        case 0xCD:
        case 0xD4:
        case 0xD5:
        case 0xE4:
        case 0xE5:
        case 0xE6:
        case 0xE7:
            encoding.immediate = Immediate::byte;
            if ((opcode == 0xD4 || opcode == 0xD5) && mode == Mode::x64) {
                encoding.valid = false;
            }
            break;
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3:
        case 0xEB:
            encoding.immediate = Immediate::byte;
            encoding.relative = true;
            break;
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99:
        case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
        case 0xC3: case 0xC9: case 0xCB: case 0xCC: case 0xCF:
        case 0xD6: case 0xD7:
        case 0xEC: case 0xED: case 0xEE: case 0xEF:
        case 0xF1: case 0xF4: case 0xF5:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
            break;
        case 0x9A:
        case 0xEA:
            encoding.valid = mode == Mode::x86;
            encoding.immediate = Immediate::far_pointer;
            break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            encoding.immediate = Immediate::address;
            break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            encoding.immediate = Immediate::byte;
            break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            encoding.immediate = Immediate::mov_register;
            break;
        case 0xC2:
        case 0xCA:
            encoding.immediate = Immediate::byte; // Adjusted to two bytes below.
            break;
        case 0xC8:
            encoding.immediate = Immediate::enter;
            break;
        case 0xCE:
            encoding.valid = mode == Mode::x86; // INTO.
            break;
        case 0xE8:
        case 0xE9:
            encoding.immediate = Immediate::operand;
            encoding.relative = true;
            break;
        case 0xF6:
        case 0xF7:
            encoding.modrm = true;
            break;
        default:
            if (opcode >= 0x50 && opcode <= 0x5F) {
                break;
            }
            // Opcodes not described above are deliberately rejected. This is
            // preferable to guessing a length and stealing bytes from the
            // following instruction.
            encoding.valid = false;
            break;
    }
    return encoding.valid;
}

[[nodiscard]] constexpr bool is_map1_no_modrm(std::uint8_t opcode) noexcept {
    if ((opcode >= 0x05 && opcode <= 0x0B) ||
        (opcode >= 0x30 && opcode <= 0x37) ||
        opcode == 0x0E || opcode == 0x77 ||
        (opcode >= 0x80 && opcode <= 0x8F) ||
        opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 ||
        opcode == 0xA8 || opcode == 0xA9 || opcode == 0xAA ||
        (opcode >= 0xC8 && opcode <= 0xCF)) {
        return true;
    }
    return false;
}

[[nodiscard]] constexpr std::size_t immediate_size(
    Immediate immediate,
    Mode mode,
    bool operand16,
    bool address_override,
    bool rex_w) noexcept {
    switch (immediate) {
        case Immediate::none:
            return 0;
        case Immediate::byte:
            return 1;
        case Immediate::operand:
            return operand_immediate_size(mode, operand16);
        case Immediate::address:
            return address_immediate_size(mode, address_override);
        case Immediate::mov_register:
            return mode == Mode::x64 && rex_w
                       ? 8u
                       : operand_immediate_size(mode, operand16);
        case Immediate::far_pointer:
            return operand_immediate_size(mode, operand16) + 2u;
        case Immediate::enter:
            return 3u;
    }
    return 0;
}

} // namespace decoder_detail

[[nodiscard]] inline bool decode_instruction(
    const std::byte* code,
    std::size_t available,
    Mode mode,
    DecodedInstruction& output) noexcept {
    using namespace decoder_detail;

    output = {};
    if (code == nullptr || available == 0) {
        return false;
    }

    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(code);
    Cursor cursor{bytes, available};

    bool operand16 = false;
    bool address_override = false;
    bool lock_prefix = false;
    bool repeat_prefix = false;
    std::uint8_t rex = 0;
    std::uint8_t prefix = 0;

    for (;;) {
        if (!cursor.peek(prefix)) {
            return false;
        }
        if (is_legacy_prefix(prefix)) {
            (void)cursor.read(prefix);
            rex = 0; // A later legacy prefix makes an earlier REX ineffective.
            if (prefix == 0x66) operand16 = true;
            if (prefix == 0x67) address_override = true;
            if (prefix == 0xF0) lock_prefix = true;
            if (prefix == 0xF2 || prefix == 0xF3) repeat_prefix = true;
            continue;
        }
        if (mode == Mode::x64 && prefix >= 0x40 && prefix <= 0x4F) {
            (void)cursor.read(rex);
            continue;
        }
        break;
    }

    bool vector_encoding = false;
    bool evex_encoding = false;
    std::uint8_t map = 0;
    std::uint8_t opcode = 0;
    std::uint8_t opcode2 = 0;

    if (prefix == 0xC5 &&
        (mode == Mode::x64 ||
         (cursor.position() + 1 < available && (bytes[cursor.position() + 1] & 0xC0u) == 0xC0u))) {
        std::uint8_t lead = 0;
        std::uint8_t vex_payload = 0;
        if (!cursor.read(lead) || !cursor.read(vex_payload)) return false;
        (void)lead;
        vector_encoding = true;
        map = 1;
    } else if (prefix == 0xC4 &&
               (mode == Mode::x64 ||
                ([&] { std::uint8_t next = 0; return cursor.peek_ahead(1, next) && (next & 0xC0u) == 0xC0u; })())) {
        std::uint8_t lead = 0;
        std::uint8_t vex_map = 0;
        std::uint8_t vex_payload = 0;
        if (!cursor.read(lead) || !cursor.read(vex_map) || !cursor.read(vex_payload)) return false;
        (void)lead;
        (void)vex_payload;
        map = static_cast<std::uint8_t>(vex_map & 0x1Fu);
        vector_encoding = true;
    } else if (prefix == 0x62 &&
               (mode == Mode::x64 ||
                ([&] { std::uint8_t next = 0; return cursor.peek_ahead(1, next) && (next & 0xC0u) == 0xC0u; })())) {
        std::uint8_t lead = 0;
        std::uint8_t evex_p0 = 0;
        std::uint8_t evex_p1 = 0;
        std::uint8_t evex_p2 = 0;
        if (!cursor.read(lead) || !cursor.read(evex_p0) ||
            !cursor.read(evex_p1) || !cursor.read(evex_p2)) return false;
        (void)lead;
        (void)evex_p2;
        if ((evex_p0 & 0x0Cu) != 0 || (evex_p1 & 0x04u) == 0) {
            return false;
        }
        map = static_cast<std::uint8_t>(evex_p0 & 0x07u);
        vector_encoding = true;
        evex_encoding = true;
    }

    if (vector_encoding) {
        if (lock_prefix || repeat_prefix || operand16 || rex != 0 ||
            (map != 1 && map != 2 && map != 3)) {
            return false;
        }
        if (!cursor.read(opcode)) return false;
    } else {
        std::uint8_t lookahead = 0;
        if (prefix == 0x8F && cursor.peek_ahead(1, lookahead) &&
            (lookahead & 0x1Fu) >= 8u) {
            return false; // AMD XOP is intentionally outside this decoder's scope.
        }
        if (!cursor.read(opcode)) return false;
        if (opcode == 0x0F) {
            opcode2 = 0;
            if (!cursor.read(opcode2)) return false;
            if (opcode2 == 0x38 || opcode2 == 0x3A) {
                const std::uint8_t map_selector = opcode2;
                if (!cursor.read(opcode)) return false;
                map = map_selector == 0x38 ? 2u : 3u;
                opcode2 = opcode;
                opcode = 0x0F;
            } else {
                map = 1;
                opcode = 0x0F;
            }
        }
    }

    Encoding encoding{};
    if (!vector_encoding && map == 0) {
        if (!decode_one_byte_opcode(opcode, mode, encoding)) return false;
    } else if (map == 1) {
        if (!vector_encoding && opcode2 == 0x0F) {
            encoding.modrm = true;
            encoding.immediate = Immediate::byte; // 3DNow! selector.
        } else if (!vector_encoding && opcode2 >= 0x80 && opcode2 <= 0x8F) {
            encoding.relative = true;
            encoding.immediate = Immediate::operand;
        } else if (!vector_encoding && opcode2 == 0x0A) {
            return false; // Reserved two-byte opcode.
        } else if (!vector_encoding && opcode2 == 0x78 && operand16) {
            encoding.modrm = true;
            encoding.immediate = Immediate::byte;
            // EXTRQ has two imm8 operands.
        } else {
            const std::uint8_t map_opcode = vector_encoding ? opcode : opcode2;
            encoding.modrm = vector_encoding
                                 ? map_opcode != 0x77
                                 : !is_map1_no_modrm(map_opcode);
            if (!vector_encoding && (map_opcode == 0x70 ||
                                     (map_opcode >= 0x71 && map_opcode <= 0x73) ||
                                     map_opcode == 0xA4 || map_opcode == 0xAC ||
                                     map_opcode == 0xBA || map_opcode == 0xC2 ||
                                     map_opcode == 0xC4 || map_opcode == 0xC5 ||
                                     map_opcode == 0xC6)) {
                encoding.immediate = Immediate::byte;
            }
            if (vector_encoding &&
                ((map_opcode >= 0x70 && map_opcode <= 0x73) ||
                 map_opcode == 0xC2 || map_opcode == 0xC4 ||
                 map_opcode == 0xC5 || map_opcode == 0xC6)) {
                encoding.immediate = Immediate::byte;
            }
        }
    } else if (map == 2) {
        encoding.modrm = true;
    } else if (map == 3) {
        encoding.modrm = true;
        encoding.immediate = Immediate::byte;
    } else {
        return false;
    }

    if (!encoding.valid) return false;

    std::uint8_t modrm = 0;
    std::uint8_t modrm_mod = 0;
    std::uint8_t modrm_reg = 0;
    std::uint8_t modrm_rm = 0;
    std::uint8_t sib_base = 0;
    bool has_sib = false;
    bool rip_relative = false;
    std::uint8_t rip_offset = 0;

    if (encoding.modrm) {
        if (!cursor.read(modrm)) return false;
        modrm_mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        modrm_reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        modrm_rm = static_cast<std::uint8_t>(modrm & 0x07u);

        if (map == 0 && opcode == 0x8F && modrm_reg != 0) return false;
        if (map == 0 && opcode == 0xFE && modrm_reg > 1) return false;

        if (modrm_mod != 3) {
            const bool address16 = mode == Mode::x86 && address_override;
            if (address16) {
                if (modrm_mod == 0 && modrm_rm == 6) {
                    if (!cursor.skip(2)) return false;
                } else if (modrm_mod == 1) {
                    if (!cursor.skip(1)) return false;
                } else if (modrm_mod == 2) {
                    if (!cursor.skip(2)) return false;
                }
            } else {
                if (modrm_rm == 4) {
                    std::uint8_t sib = 0;
                    if (!cursor.read(sib)) return false;
                    has_sib = true;
                    sib_base = static_cast<std::uint8_t>(sib & 0x07u);
                }

                if (modrm_mod == 0) {
                    if ((!has_sib && modrm_rm == 5) || (has_sib && sib_base == 5)) {
                        rip_offset = static_cast<std::uint8_t>(cursor.position());
                        rip_relative = mode == Mode::x64 && !address_override && !has_sib &&
                                       modrm_rm == 5;
                        if (!cursor.skip(4)) return false;
                    }
                } else if (modrm_mod == 1) {
                    if (!cursor.skip(1)) return false;
                } else if (modrm_mod == 2) {
                    if (!cursor.skip(4)) return false;
                }
            }
        }

        if (map == 0 && opcode == 0xF6 && modrm_reg <= 1) {
            encoding.immediate = Immediate::byte;
        } else if (map == 0 && opcode == 0xF7 && modrm_reg <= 1) {
            encoding.immediate = Immediate::operand;
        }
    }

    std::size_t immediate_bytes = immediate_size(
        encoding.immediate, mode, operand16, address_override, (rex & 0x08u) != 0);

    if (map == 0 && (opcode == 0xC2 || opcode == 0xCA)) {
        immediate_bytes = 2;
    }
    if (encoding.relative && mode == Mode::x64 &&
        encoding.immediate == Immediate::operand) {
        immediate_bytes = 4; // Near branches in long mode always carry rel32.
    }
    if (!vector_encoding && map == 1 && opcode2 == 0x78 && operand16) {
        immediate_bytes = 2; // EXTRQ has two imm8 operands.
    }
    if (!vector_encoding && map == 1 && opcode2 == 0x79 && operand16) {
        immediate_bytes = 2; // INSERTQ has two imm8 operands.
    }

    if (encoding.relative) {
        output.has_relative_operand = true;
        output.relative_offset = static_cast<std::uint8_t>(cursor.position());
        output.relative_size = static_cast<std::uint8_t>(
            mode == Mode::x64 && encoding.immediate == Immediate::operand
                ? 4u
                : immediate_bytes);
    }

    if (rip_relative) {
        output.has_rip_relative_operand = true;
        output.rip_displacement_offset = rip_offset;
    }

    if (immediate_bytes != 0 && !cursor.skip(immediate_bytes)) {
        output = {};
        return false;
    }

    if (cursor.position() == 0 || cursor.position() > kMaximumInstructionLength) {
        output = {};
        return false;
    }

    output.length = static_cast<std::uint8_t>(cursor.position());
    if (vector_encoding) {
        output.opcode = opcode;
        output.opcode2 = 0;
    } else if (map == 0) {
        output.opcode = opcode;
    } else {
        output.opcode = 0x0F;
        output.opcode2 = opcode2;
    }
    output.modrm_reg = modrm_reg;

    (void)evex_encoding;
    return true;
}

} // namespace tessera::detail::x86
