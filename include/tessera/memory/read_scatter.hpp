#pragma once
#include "tessera/core/error.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/process/process.hpp"

#include <optional>
#include <span>
#include <vector>
namespace tessera {
struct MemoryReadRequest {
    Address address{};
    std::size_t size = 0;
};
struct MemoryReadResult {
    std::vector<std::byte> bytes{};
    std::optional<Error> error{};
    [[nodiscard]] bool succeeded() const noexcept { return !error; }
};
[[nodiscard]] Result<std::vector<MemoryReadResult>> read_scatter(const Process&,
                                                                 std::span<const MemoryReadRequest>,
                                                                 std::size_t coalesce_gap = 4096,
                                                                 std::size_t max_batch_size = 1u << 20);
} // namespace tessera
