#include "tessera/resolver/resolver.hpp"

#include <array>
#include <cstring>

#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_backend.hpp"
#include "tessera/memory/memory_reader.hpp"

namespace tessera::resolve {

namespace detail {

namespace {

template <std::size_t N>
[[nodiscard]] constexpr bool in_byte_set(std::uint8_t val,
                                         const std::array<std::uint8_t, N>& set) noexcept {
    for (const std::uint8_t item : set) {
        if (item == val) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] Result<std::size_t> read_code_window(const ProcessAddress& pa,
                                                   std::span<std::byte, 16> out) noexcept {
    if (pa.is_null()) {
        return fail(ErrorCode::NullAddress, "read_code_window");
    }
    return memory_backend(pa.process()).read(pa.address(), out);
}

} // namespace

Result<ProcessAddress> deref_impl(const ProcessAddress& pa) noexcept {
    return pa.deref();
}

Result<ProcessAddress> offset_impl(const ProcessAddress& pa, std::int64_t delta) noexcept {
    return pa.offset(delta);
}

Result<ProcessAddress> pointer_chain_impl(const ProcessAddress& pa,
                                          std::span<const std::int64_t> offsets) noexcept {
    if (pa.is_null()) {
        return fail(ErrorCode::NullAddress, "resolve::pointer_chain");
    }
    ProcessAddress cur = pa;
    for (std::size_t i = 0; i < offsets.size(); ++i) {
        auto next_off = cur.offset(offsets[i]);
        if (!next_off) {
            return next_off;
        }
        cur = *next_off;
        if (i + 1 < offsets.size()) {
            auto derefed = cur.deref();
            if (!derefed) {
                return derefed;
            }
            cur = *derefed;
        }
    }
    return cur;
}

Result<ProcessAddress> rel32_impl(const ProcessAddress& pa,
                                  std::size_t disp_offset,
                                  std::size_t instr_len) noexcept {
    if (pa.is_null()) {
        return fail(ErrorCode::NullAddress, "resolve::rel32");
    }
    if (instr_len == 0 || disp_offset + sizeof(std::int32_t) > instr_len) {
        return fail(ErrorCode::InvalidArgument,
                    "resolve::rel32",
                    0,
                    "disp_offset + 4 cannot exceed instr_len");
    }
    auto disp_addr = pa.offset(static_cast<std::int64_t>(disp_offset));
    if (!disp_addr) {
        return disp_addr;
    }
    auto disp = disp_addr->read<std::int32_t>();
    if (!disp) {
        return std::unexpected(disp.error());
    }
    auto next_ip = pa.offset(static_cast<std::int64_t>(instr_len));
    if (!next_ip) {
        return next_ip;
    }
    return next_ip->offset(*disp);
}

Result<ProcessAddress> follow_branch_impl(const ProcessAddress& pa) noexcept {
    std::array<std::byte, 16> raw{};
    auto n_res = read_code_window(pa, raw);
    if (!n_res) {
        return std::unexpected(n_res.error());
    }
    const std::size_t n = *n_res;
    if (n < 2) {
        return fail(ErrorCode::PartialTransfer,
                    "resolve::follow_branch",
                    0,
                    "Insufficient readable code bytes");
    }

    const auto b0 = std::to_integer<std::uint8_t>(raw[0]);
    std::size_t instr_len = 0;
    std::int64_t disp = 0;

    if (b0 == 0xE8u || b0 == 0xE9u) {
        if (n < 5) {
            return fail(ErrorCode::PartialTransfer,
                        "resolve::follow_branch",
                        0,
                        "Truncated E8/E9 rel32 branch instruction");
        }
        std::int32_t d32 = 0;
        std::memcpy(&d32, raw.data() + 1, sizeof(d32));
        instr_len = 5;
        disp = d32;
    } else if (b0 == 0xEBu || (b0 >= 0x70u && b0 <= 0x7Fu)) {
        instr_len = 2;
        disp = static_cast<std::int8_t>(std::to_integer<std::uint8_t>(raw[1]));
    } else if (b0 == 0x0Fu) {
        const auto b1 = std::to_integer<std::uint8_t>(raw[1]);
        if (b1 >= 0x80u && b1 <= 0x8Fu) {
            if (n < 6) {
                return fail(ErrorCode::PartialTransfer,
                            "resolve::follow_branch",
                            0,
                            "Truncated 0F 8x rel32 conditional branch");
            }
            std::int32_t d32 = 0;
            std::memcpy(&d32, raw.data() + 2, sizeof(d32));
            instr_len = 6;
            disp = d32;
        } else {
            return fail(ErrorCode::UnsupportedInstruction,
                        "resolve::follow_branch",
                        0,
                        "Instruction at address is not a supported direct branch");
        }
    } else {
        return fail(ErrorCode::UnsupportedInstruction,
                    "resolve::follow_branch",
                    0,
                    "Instruction at address is not a supported direct branch");
    }

    auto next_ip = pa.offset(static_cast<std::int64_t>(instr_len));
    if (!next_ip) {
        return next_ip;
    }
    return next_ip->offset(disp);
}

Result<ProcessAddress> follow_rip_impl(const ProcessAddress& pa) noexcept {
    if (pa.process().pointer_size() != 8) {
        return fail(ErrorCode::UnsupportedArchitecture,
                    "resolve::follow_rip",
                    0,
                    "RIP-relative addressing is only valid for x64 target processes");
    }

    std::array<std::byte, 16> raw{};
    auto n_res = read_code_window(pa, raw);
    if (!n_res) {
        return std::unexpected(n_res.error());
    }
    const std::size_t n = *n_res;

    std::size_t i = 0;
    while (i < n && i < 2) {
        const auto pfx = std::to_integer<std::uint8_t>(raw[i]);
        if (pfx == 0x66u || pfx == 0xF2u || pfx == 0xF3u) {
            ++i;
        } else {
            break;
        }
    }

    if (i < n && (std::to_integer<std::uint8_t>(raw[i]) & 0xF0u) == 0x40u) {
        ++i; // REX prefix
    }

    if (i >= n) {
        return fail(ErrorCode::PartialTransfer, "resolve::follow_rip");
    }

    // Documented subset of x64 instructions whose disp32 is the final field (no trailing immediate):
    static constexpr std::array<std::uint8_t, 25> kOp1{
        0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29, 0x2B, 0x31,
        0x33, 0x39, 0x3B, 0x63, 0x85, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8D, 0xFF};
    static constexpr std::array<std::uint8_t, 20> kOp2{
        0x10, 0x11, 0x28, 0x29, 0x2E, 0x2F, 0x51, 0x54, 0x57, 0x58,
        0x59, 0x5C, 0x5E, 0x6F, 0x7F, 0xAF, 0xB6, 0xB7, 0xBE, 0xBF};

    const auto op = std::to_integer<std::uint8_t>(raw[i]);
    std::size_t modrm_at = 0;
    if (op == 0x0Fu) {
        if (i + 1 >= n) {
            return fail(ErrorCode::PartialTransfer, "resolve::follow_rip");
        }
        const auto op2 = std::to_integer<std::uint8_t>(raw[i + 1]);
        if (!in_byte_set(op2, kOp2)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "resolve::follow_rip",
                        0,
                        "Unsupported two-byte opcode for follow_rip");
        }
        modrm_at = i + 2;
    } else {
        if (!in_byte_set(op, kOp1)) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "resolve::follow_rip",
                        0,
                        "Unsupported one-byte opcode for follow_rip");
        }
        modrm_at = i + 1;
    }

    if (modrm_at >= n) {
        return fail(ErrorCode::PartialTransfer, "resolve::follow_rip");
    }

    const auto modrm = std::to_integer<std::uint8_t>(raw[modrm_at]);
    if ((modrm & 0xC7u) != 0x05u) {
        return fail(ErrorCode::UnsupportedInstruction,
                    "resolve::follow_rip",
                    0,
                    "ModR/M does not encode RIP-relative [rip+disp32] operand");
    }

    if (op == 0xFFu) {
        const auto reg = (modrm >> 3u) & 0x07u;
        if (reg != 2u && reg != 4u) {
            return fail(ErrorCode::UnsupportedInstruction,
                        "resolve::follow_rip",
                        0,
                        "0xFF opcode is neither call (/2) nor jmp (/4)");
        }
    }

    if (modrm_at + 5 > n) {
        return fail(ErrorCode::PartialTransfer,
                    "resolve::follow_rip",
                    0,
                    "Truncated RIP-relative disp32 operand");
    }

    std::int32_t disp = 0;
    std::memcpy(&disp, raw.data() + modrm_at + 1, sizeof(disp));
    auto next_ip = pa.offset(static_cast<std::int64_t>(modrm_at + 5));
    if (!next_ip) {
        return next_ip;
    }
    return next_ip->offset(disp);
}

Result<ProcessAddress> abs32_impl(const ProcessAddress& pa,
                                  std::size_t operand_offset) noexcept {
    if (pa.process().pointer_size() != 4) {
        return fail(ErrorCode::UnsupportedArchitecture,
                    "resolve::abs32",
                    0,
                    "abs32 operand resolution is only valid for x86 target processes");
    }
    if (pa.is_null()) {
        return fail(ErrorCode::NullAddress, "resolve::abs32");
    }
    auto op_addr = pa.offset(static_cast<std::int64_t>(operand_offset));
    if (!op_addr) {
        return op_addr;
    }
    auto val32 = op_addr->read<std::uint32_t>();
    if (!val32) {
        return std::unexpected(val32.error());
    }
    if (*val32 == 0) {
        return fail(ErrorCode::NullAddress, "resolve::abs32", 0, "Resolved abs32 operand is null");
    }
    return ProcessAddress{pa.process(), Address{static_cast<std::uint64_t>(*val32)}};
}

} // namespace detail

Result<Rva> abs32_to_rva(const ProcessAddress& pa,
                         std::size_t operand_offset,
                         std::uint64_t image_base) noexcept {
    auto abs_res = detail::abs32_impl(pa, operand_offset);
    if (!abs_res) {
        return std::unexpected(abs_res.error());
    }
    const std::uint64_t va = abs_res->value();
    if (va < image_base) {
        return fail(ErrorCode::OutOfRange,
                    "resolve::abs32_to_rva",
                    0,
                    "Absolute operand is below module image_base");
    }
    const std::uint64_t diff = va - image_base;
    if (diff > 0xFFFFFFFFULL) {
        return fail(ErrorCode::AddressOverflow, "resolve::abs32_to_rva");
    }
    return Rva{static_cast<std::uint32_t>(diff)};
}

} // namespace tessera::resolve
