#pragma once
#include <vector>
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/process/process.hpp"
namespace tessera {
struct MemorySnapshot{Address base{};std::vector<std::byte> bytes{};[[nodiscard]]static Result<MemorySnapshot> capture(const Process&,AddressRange);};
struct ChangedRange{std::size_t offset=0;std::vector<std::byte> old_bytes{},new_bytes{};};
[[nodiscard]]Result<std::vector<ChangedRange>> diff(const MemorySnapshot&,const MemorySnapshot&);
} // namespace tessera
