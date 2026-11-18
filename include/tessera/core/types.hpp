#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "tessera/core/checked_math.hpp"
#include "tessera/core/result.hpp"

namespace tessera {

enum class Ownership : std::uint8_t {
    Borrowed,
    Owned,
};

class [[nodiscard]] ProcessId {
public:
    constexpr ProcessId() noexcept = default;
    constexpr explicit ProcessId(std::uint32_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
    constexpr explicit operator bool() const noexcept { return valid(); }

    [[nodiscard]] constexpr auto operator<=>(const ProcessId&) const noexcept = default;

private:
    std::uint32_t value_ = 0;
};

class [[nodiscard]] Rva {
public:
    constexpr Rva() noexcept = default;
    constexpr explicit Rva(std::uint32_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }

    [[nodiscard]] constexpr Result<Rva> offset(std::int64_t delta) const noexcept {
        auto next = checked_offset<std::uint32_t>(value_, delta);
        if (!next) {
            return std::unexpected(next.error());
        }
        return Rva{*next};
    }

    [[nodiscard]] constexpr auto operator<=>(const Rva&) const noexcept = default;

private:
    std::uint32_t value_ = 0;
};

class [[nodiscard]] Address {
public:
    constexpr Address() noexcept = default;
    constexpr explicit Address(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] static Address from_ptr(const void* ptr) noexcept {
        return Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(ptr))};
    }

    [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool is_null() const noexcept { return value_ == 0; }
    constexpr explicit operator bool() const noexcept { return value_ != 0; }

    [[nodiscard]] constexpr Result<Address> offset(std::int64_t delta) const noexcept {
        if (is_null()) {
            return std::unexpected(Error{
                .code = ErrorCode::NullAddress,
                .native = 0,
                .operation = "Address::offset",
                .detail = {},
            });
        }
        auto next = checked_offset<std::uint64_t>(value_, delta);
        if (!next) {
            return std::unexpected(next.error());
        }
        if (*next == 0) {
            return std::unexpected(Error{
                .code = ErrorCode::NullAddress,
                .native = 0,
                .operation = "Address::offset",
                .detail = {},
            });
        }
        return Address{*next};
    }

    [[nodiscard]] constexpr Result<Address> add_rva(Rva rva) const noexcept {
        if (is_null()) {
            return std::unexpected(Error{
                .code = ErrorCode::NullAddress,
                .native = 0,
                .operation = "Address::add_rva",
                .detail = {},
            });
        }
        auto next = checked_add<std::uint64_t>(value_, static_cast<std::uint64_t>(rva.value()));
        if (!next) {
            return std::unexpected(next.error());
        }
        return Address{*next};
    }

    [[nodiscard]] constexpr Address align_down(std::uint64_t alignment) const noexcept {
        if (alignment <= 1) {
            return *this;
        }
        return Address{value_ - (value_ % alignment)};
    }

    [[nodiscard]] constexpr Result<Address> align_up(std::uint64_t alignment) const noexcept {
        if (alignment <= 1) {
            return *this;
        }
        const std::uint64_t rem = value_ % alignment;
        if (rem == 0) {
            return *this;
        }
        auto next = checked_add<std::uint64_t>(value_, alignment - rem);
        if (!next) {
            return std::unexpected(next.error());
        }
        return Address{*next};
    }

    [[nodiscard]] constexpr auto operator<=>(const Address&) const noexcept = default;

private:
    std::uint64_t value_ = 0;
};

class [[nodiscard]] AddressRange {
public:
    constexpr AddressRange() noexcept = default;
    constexpr AddressRange(Address begin, std::uint64_t size) noexcept
        : begin_(begin), size_(size) {}

    [[nodiscard]] static constexpr Result<AddressRange> from_bounds(Address begin, Address end) noexcept {
        if (end < begin) {
            return std::unexpected(Error{
                .code = ErrorCode::InvalidArgument,
                .native = 0,
                .operation = "AddressRange::from_bounds",
                .detail = {},
            });
        }
        return AddressRange{begin, end.value() - begin.value()};
    }

    [[nodiscard]] constexpr Address begin() const noexcept { return begin_; }
    [[nodiscard]] constexpr std::uint64_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0 || begin_.is_null(); }

    [[nodiscard]] constexpr Result<Address> end() const noexcept {
        if (begin_.is_null() && size_ == 0) {
            return Address{0};
        }
        auto e = checked_add<std::uint64_t>(begin_.value(), size_);
        if (!e) {
            return std::unexpected(e.error());
        }
        return Address{*e};
    }

    [[nodiscard]] constexpr bool contains(Address addr) const noexcept {
        if (empty() || addr.is_null() || addr < begin_) {
            return false;
        }
        return (addr.value() - begin_.value()) < size_;
    }

    [[nodiscard]] constexpr bool contains_range(const AddressRange& other) const noexcept {
        if (empty() || other.empty() || other.begin_ < begin_) {
            return false;
        }
        const std::uint64_t rel = other.begin_.value() - begin_.value();
        return rel <= size_ && other.size_ <= (size_ - rel);
    }

    [[nodiscard]] constexpr bool overlaps(const AddressRange& other) const noexcept {
        if (empty() || other.empty()) {
            return false;
        }
        auto this_end = end();
        auto other_end = other.end();
        if (!this_end || !other_end) {
            return false;
        }
        return begin_ < *other_end && other.begin_ < *this_end;
    }

    [[nodiscard]] constexpr Result<AddressRange> subrange(std::uint64_t offset_bytes,
                                                          std::uint64_t sub_size) const noexcept {
        if (offset_bytes > size_ || sub_size > (size_ - offset_bytes)) {
            return std::unexpected(Error{
                .code = ErrorCode::OutOfRange,
                .native = 0,
                .operation = "AddressRange::subrange",
                .detail = {},
            });
        }
        auto sub_begin = checked_add<std::uint64_t>(begin_.value(), offset_bytes);
        if (!sub_begin) {
            return std::unexpected(sub_begin.error());
        }
        return AddressRange{Address{*sub_begin}, sub_size};
    }

    [[nodiscard]] constexpr Result<Rva> to_rva(Address addr) const noexcept {
        if (!contains(addr)) {
            return std::unexpected(Error{
                .code = ErrorCode::OutOfRange,
                .native = 0,
                .operation = "AddressRange::to_rva",
                .detail = {},
            });
        }
        const std::uint64_t diff = addr.value() - begin_.value();
        if (diff > (std::numeric_limits<std::uint32_t>::max)()) {
            return std::unexpected(Error{
                .code = ErrorCode::AddressOverflow,
                .native = 0,
                .operation = "AddressRange::to_rva",
                .detail = {},
            });
        }
        return Rva{static_cast<std::uint32_t>(diff)};
    }

    [[nodiscard]] constexpr Result<Address> at_rva(Rva rva) const noexcept {
        if (empty() || static_cast<std::uint64_t>(rva.value()) >= size_) {
            return std::unexpected(Error{
                .code = ErrorCode::OutOfRange,
                .native = 0,
                .operation = "AddressRange::at_rva",
                .detail = {},
            });
        }
        return begin_.add_rva(rva);
    }

    [[nodiscard]] constexpr auto operator<=>(const AddressRange&) const noexcept = default;

private:
    Address begin_{};
    std::uint64_t size_ = 0;
};

} // namespace tessera

namespace std {

template <>
struct hash<tessera::Address> {
    [[nodiscard]] std::size_t operator()(const tessera::Address& addr) const noexcept {
        return std::hash<std::uint64_t>{}(addr.value());
    }
};

template <>
struct hash<tessera::Rva> {
    [[nodiscard]] std::size_t operator()(const tessera::Rva& rva) const noexcept {
        return std::hash<std::uint32_t>{}(rva.value());
    }
};

template <>
struct hash<tessera::ProcessId> {
    [[nodiscard]] std::size_t operator()(const tessera::ProcessId& pid) const noexcept {
        return std::hash<std::uint32_t>{}(pid.value());
    }
};

} // namespace std
