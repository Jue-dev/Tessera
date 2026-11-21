#include "tessera/memory/memory_snapshot.hpp"

#include <cstddef>
#include <limits>
#include <new>
#include <utility>

#include "tessera/memory/memory_reader.hpp"

namespace tessera {

Result<MemorySnapshot> MemorySnapshot::capture(const Process& process,
                                                AddressRange range) {
    if (range.empty() ||
        range.size() >
            static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return fail(ErrorCode::InvalidArgument, "MemorySnapshot::capture");
    }

    MemoryReader reader{process};
    auto bytes = reader.read_bytes(range.begin(),
                                   static_cast<std::size_t>(range.size()));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }

    return MemorySnapshot{range.begin(), std::move(*bytes)};
}

Result<std::vector<ChangedRange>> diff(const MemorySnapshot& before,
                                       const MemorySnapshot& after) {
    if (before.base != after.base ||
        before.bytes.size() != after.bytes.size()) {
        return fail(ErrorCode::InvalidArgument, "MemorySnapshot::diff", 0,
                    "Snapshots must describe the same base and byte count");
    }

    try {
        std::vector<ChangedRange> changes;
        std::size_t index = 0;
        while (index < before.bytes.size()) {
            if (before.bytes[index] == after.bytes[index]) {
                ++index;
                continue;
            }

            const std::size_t begin = index;
            while (index < before.bytes.size() &&
                   before.bytes[index] != after.bytes[index]) {
                ++index;
            }

            ChangedRange changed{};
            changed.offset = begin;
            changed.old_bytes.assign(
                before.bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                before.bytes.begin() + static_cast<std::ptrdiff_t>(index));
            changed.new_bytes.assign(
                after.bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                after.bytes.begin() + static_cast<std::ptrdiff_t>(index));
            changes.push_back(std::move(changed));
        }

        return changes;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "MemorySnapshot::diff");
    }
}

} // namespace tessera
