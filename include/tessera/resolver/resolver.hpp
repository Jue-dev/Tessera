#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/process_address.hpp"

namespace tessera::resolve {

namespace detail {

[[nodiscard]] Result<ProcessAddress> deref_impl(const ProcessAddress& pa) noexcept;
[[nodiscard]] Result<ProcessAddress> offset_impl(const ProcessAddress& pa, std::int64_t delta) noexcept;
[[nodiscard]] Result<ProcessAddress> pointer_chain_impl(const ProcessAddress& pa,
                                                        std::span<const std::int64_t> offsets) noexcept;
[[nodiscard]] Result<ProcessAddress> rel32_impl(const ProcessAddress& pa,
                                                std::size_t disp_offset,
                                                std::size_t instr_len) noexcept;
[[nodiscard]] Result<ProcessAddress> follow_branch_impl(const ProcessAddress& pa) noexcept;
[[nodiscard]] Result<ProcessAddress> follow_rip_impl(const ProcessAddress& pa) noexcept;
[[nodiscard]] Result<ProcessAddress> abs32_impl(const ProcessAddress& pa,
                                                std::size_t operand_offset) noexcept;

[[nodiscard]] Result<ProcessAddress> step_instructions_impl(
    const ProcessAddress& pa, std::size_t count) noexcept;
[[nodiscard]] Result<ProcessAddress> find_next_call_impl(
    const ProcessAddress& pa, std::size_t max_bytes) noexcept;
[[nodiscard]] Result<ProcessAddress> find_next_rip_relative_impl(
    const ProcessAddress& pa, std::size_t max_bytes) noexcept;
[[nodiscard]] Result<ProcessAddress> resolve_operand_target_impl(
    const ProcessAddress& pa) noexcept;
[[nodiscard]] Result<ProcessAddress> resolve_thunk_chain_impl(
    const ProcessAddress& pa, std::size_t max_hops) noexcept;

struct DerefFn {
    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return deref_impl(pa);
    }
};

struct OffsetAdapter {
    std::int64_t delta = 0;

    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return offset_impl(pa, delta);
    }
};

struct PointerChainAdapter {
    std::vector<std::int64_t> offsets{};

    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return pointer_chain_impl(pa, offsets);
    }
};

struct Rel32Adapter {
    std::size_t disp_offset = 1;
    std::size_t instr_len = 5;

    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return rel32_impl(pa, disp_offset, instr_len);
    }
};

struct FollowBranchFn {
    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return follow_branch_impl(pa);
    }
};

struct FollowRipFn {
    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return follow_rip_impl(pa);
    }
};

struct Abs32Adapter {
    std::size_t operand_offset = 1;

    [[nodiscard]] Result<ProcessAddress> operator()(const ProcessAddress& pa) const noexcept {
        return abs32_impl(pa, operand_offset);
    }
};

} // namespace detail

inline constexpr detail::DerefFn deref{};
inline constexpr detail::FollowBranchFn follow_branch{};
inline constexpr detail::FollowRipFn follow_rip{};

[[nodiscard]] inline constexpr detail::OffsetAdapter offset(std::int64_t delta) noexcept {
    return detail::OffsetAdapter{delta};
}

// Cheat-Engine style pointer chain: [[base + o1] + o2] + o3.
// Every offset except the last is followed by a pointer dereference; the last offset is only added.
[[nodiscard]] inline detail::PointerChainAdapter pointer_chain(
    std::span<const std::int64_t> offsets) {
    return detail::PointerChainAdapter{
        std::vector<std::int64_t>(offsets.begin(), offsets.end())};
}

template <std::convertible_to<std::int64_t>... Offs>
    requires (sizeof...(Offs) > 0)
[[nodiscard]] inline detail::PointerChainAdapter pointer_chain(Offs... offsets) {
    return detail::PointerChainAdapter{
        std::vector<std::int64_t>{static_cast<std::int64_t>(offsets)...}};
}

[[nodiscard]] inline constexpr detail::Rel32Adapter rel32(std::size_t disp_offset = 1,
                                                          std::size_t instr_len = 5) noexcept {
    return detail::Rel32Adapter{disp_offset, instr_len};
}

[[nodiscard]] inline constexpr detail::Abs32Adapter abs32(
    std::size_t operand_offset = 1) noexcept {
    return detail::Abs32Adapter{operand_offset};
}

// Reads a 32-bit absolute operand (x86 target only) and converts it to an RVA relative to image_base.
[[nodiscard]] Result<Rva> abs32_to_rva(const ProcessAddress& pa,
                                       std::size_t operand_offset,
                                       std::uint64_t image_base) noexcept;

} // namespace tessera::resolve

#include "tessera/resolver/address_cursor.hpp"
