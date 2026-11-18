#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/process_address.hpp"
#include "tessera/resolver/resolver.hpp"
#include "tessera/scanner/scanner.hpp"

namespace tessera {

// Fluent dot-chaining cursor over Result<ProcessAddress>.
// If an earlier step fails, subsequent steps short-circuit and propagate the first error.
class [[nodiscard]] AddressCursor {
public:
    explicit AddressCursor(Process proc, Result<Address> initial) noexcept
        : state_(initial ? Result<ProcessAddress>{ProcessAddress{std::move(proc), *initial}}
                         : std::unexpected(initial.error())) {}

    explicit AddressCursor(Result<ProcessAddress> initial) noexcept
        : state_(std::move(initial)) {}

    [[nodiscard]] AddressCursor deref() const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::deref_impl(*state_)};
    }

    [[nodiscard]] AddressCursor offset(std::int64_t n) const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::offset_impl(*state_, n)};
    }

    // Cheat-Engine style pointer chain: [[a + o1] + o2] + o3 (last offset is only added).
    [[nodiscard]] AddressCursor pointer_chain(std::span<const std::int64_t> offsets) const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::pointer_chain_impl(*state_, offsets)};
    }

    template <std::convertible_to<std::int64_t>... Offs>
        requires (sizeof...(Offs) > 0)
    [[nodiscard]] AddressCursor pointer_chain(Offs... offsets) const noexcept {
        const std::array<std::int64_t, sizeof...(Offs)> arr{static_cast<std::int64_t>(offsets)...};
        return pointer_chain(std::span<const std::int64_t>(arr));
    }

    [[nodiscard]] AddressCursor rel32(std::size_t disp_off = 1,
                                      std::size_t instr_len = 5) const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::rel32_impl(*state_, disp_off, instr_len)};
    }

    [[nodiscard]] AddressCursor follow_branch() const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::follow_branch_impl(*state_)};
    }

    [[nodiscard]] AddressCursor follow_rip() const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::follow_rip_impl(*state_)};
    }

    [[nodiscard]] AddressCursor abs32(std::size_t operand_off = 1) const noexcept {
        if (!state_) {
            return *this;
        }
        return AddressCursor{resolve::detail::abs32_impl(*state_, operand_off)};
    }

    // Terminal operations
    [[nodiscard]] Result<ProcessAddress> resolve() const noexcept { return state_; }

    [[nodiscard]] Result<Address> address() const noexcept {
        if (!state_) {
            return std::unexpected(state_.error());
        }
        return state_->address();
    }

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read() const noexcept {
        if (!state_) {
            return std::unexpected(state_.error());
        }
        return state_->read<T>();
    }

private:
    Result<ProcessAddress> state_;
};

inline AddressCursor ProcessAddress::cursor() const noexcept {
    return AddressCursor{Result<ProcessAddress>{*this}};
}

inline AddressCursor Scanner::find_first_cursor(AddressRange range,
                                                const Pattern& pattern,
                                                const ScanOptions& options) const {
    return AddressCursor{process_, find_first(range, pattern, options)};
}

inline AddressCursor Scanner::find_unique_cursor(AddressRange range,
                                                 const Pattern& pattern,
                                                 const ScanOptions& options) const {
    return AddressCursor{process_, find_unique(range, pattern, options)};
}

} // namespace tessera
