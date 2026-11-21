#pragma once
#include "tessera/core/function_ref.hpp"
#include "tessera/scanner/scanner.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
namespace tessera::scanner_detail {
using ChunkCallback = FunctionRef<bool(std::span<const std::byte>, std::size_t, Address, std::uint64_t, std::uint64_t)>;
[[nodiscard]] Result<ScanStats> for_each_readable_chunk(const Process&, AddressRange, std::size_t,
    const ScanOptions&, bool&, ChunkCallback,
    ScanReadPolicy read_policy = ScanReadPolicy::BestEffort,
    std::vector<std::byte>* workspace = nullptr);
} // namespace tessera::scanner_detail
