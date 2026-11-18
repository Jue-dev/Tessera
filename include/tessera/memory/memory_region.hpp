#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "tessera/core/enum_flags.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

enum class MemoryState : std::uint8_t {
    Free,
    Reserved,
    Committed,
};

enum class MemoryType : std::uint8_t {
    Unknown,
    Private,
    Mapped,
    Image,
};

enum class MemoryProtection : std::uint32_t {
    None = 0,
    NoAccess = 1u << 0,
    Read = 1u << 1,
    Write = 1u << 2,
    Execute = 1u << 3,
    CopyOnWrite = 1u << 4,
    Guard = 1u << 5,
    NoCache = 1u << 6,
    WriteCombine = 1u << 7,
    ReadWrite = Read | Write,
    ExecuteRead = Execute | Read,
    ExecuteReadWrite = Execute | Read | Write,
    ExecuteWriteCopy = Execute | Read | CopyOnWrite,
};

} // namespace tessera

TESSERA_ENABLE_ENUM_FLAGS(tessera::MemoryProtection);

namespace tessera {

struct MemoryRegionInfo {
    Address base{};
    Address allocation_base{};
    std::uint64_t size = 0;
    MemoryState state = MemoryState::Free;
    MemoryProtection protection = MemoryProtection::None;
    MemoryProtection allocation_protection = MemoryProtection::None;
    MemoryType type = MemoryType::Unknown;

    [[nodiscard]] constexpr AddressRange range() const noexcept {
        return AddressRange{base, size};
    }

    [[nodiscard]] constexpr bool is_committed() const noexcept {
        return state == MemoryState::Committed;
    }

    [[nodiscard]] constexpr bool is_guard() const noexcept {
        return has_flag(protection, MemoryProtection::Guard);
    }

    [[nodiscard]] constexpr bool is_readable() const noexcept {
        return is_committed() && !is_guard() && !has_flag(protection, MemoryProtection::NoAccess) &&
               any_flag(protection,
                        MemoryProtection::Read | MemoryProtection::Write |
                            MemoryProtection::Execute | MemoryProtection::CopyOnWrite);
    }

    [[nodiscard]] constexpr bool is_writable() const noexcept {
        return is_committed() && !is_guard() &&
               any_flag(protection, MemoryProtection::Write | MemoryProtection::CopyOnWrite);
    }

    [[nodiscard]] constexpr bool is_executable() const noexcept {
        return is_committed() && !is_guard() && has_flag(protection, MemoryProtection::Execute);
    }
};

struct RegionFilter {
    bool executable_only = false;
    bool writable_only = false;
    bool include_guard_pages = false;
};

[[nodiscard]] constexpr bool matches_region_filter(const MemoryRegionInfo& region,
                                                   const RegionFilter& filter) noexcept {
    if (!region.is_committed() || has_flag(region.protection, MemoryProtection::NoAccess)) {
        return false;
    }
    if (!filter.include_guard_pages && region.is_guard()) {
        return false;
    }
    const bool has_read = any_flag(region.protection,
                                   MemoryProtection::Read | MemoryProtection::Write |
                                       MemoryProtection::Execute | MemoryProtection::CopyOnWrite);
    if (!has_read) {
        return false;
    }
    if (filter.executable_only && !has_flag(region.protection, MemoryProtection::Execute)) {
        return false;
    }
    if (filter.writable_only &&
        !any_flag(region.protection, MemoryProtection::Write | MemoryProtection::CopyOnWrite)) {
        return false;
    }
    return true;
}

[[nodiscard]] Result<std::vector<MemoryRegionInfo>> enumerate_regions(
    const Process& process,
    AddressRange bounds = {},
    RegionFilter filter = {});

[[nodiscard]] std::vector<AddressRange> merge_contiguous_regions(
    std::span<const MemoryRegionInfo> regions,
    AddressRange clip_bounds = {});

} // namespace tessera
