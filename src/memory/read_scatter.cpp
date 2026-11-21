#include "tessera/memory/read_scatter.hpp"

#include <algorithm>
#include <new>
#include <utility>

#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_backend.hpp"

namespace tessera {

Result<std::vector<MemoryReadResult>> read_scatter(
    const Process& process, std::span<const MemoryReadRequest> requests,
    std::size_t coalesce_gap, std::size_t max_batch_size) {
    if (max_batch_size == 0) {
        return fail(ErrorCode::InvalidArgument, "read_scatter");
    }

    struct IndexedRequest {
        std::size_t index = 0;
        std::uint64_t begin = 0;
        std::uint64_t end = 0;
    };

    try {
        std::vector<MemoryReadResult> results(requests.size());
        std::vector<IndexedRequest> ordered;
        ordered.reserve(requests.size());

        for (std::size_t i = 0; i < requests.size(); ++i) {
            const auto& request = requests[i];
            if (request.size == 0) {
                continue;
            }
            if (request.size > max_batch_size) {
                results[i].error = make_error(ErrorCode::OutOfRange,
                                               "read_scatter");
                continue;
            }
            if (request.address.is_null()) {
                results[i].error = make_error(ErrorCode::NullAddress,
                                               "read_scatter");
                continue;
            }

            auto end = checked_add<std::uint64_t>(
                request.address.value(),
                static_cast<std::uint64_t>(request.size));
            if (!end) {
                results[i].error = end.error();
                continue;
            }

            ordered.push_back(
                IndexedRequest{i, request.address.value(), *end});
        }

        std::sort(ordered.begin(), ordered.end(),
                  [](const IndexedRequest& lhs, const IndexedRequest& rhs) {
                      return lhs.begin < rhs.begin;
                  });

        const auto& backend = memory_backend(process);
        std::size_t cursor = 0;
        while (cursor < ordered.size()) {
            std::size_t last = cursor + 1;
            const std::uint64_t batch_begin = ordered[cursor].begin;
            std::uint64_t batch_end = ordered[cursor].end;

            while (last < ordered.size()) {
                const auto& next = ordered[last];
                const std::uint64_t gap =
                    next.begin > batch_end ? next.begin - batch_end : 0;
                if (gap > coalesce_gap || next.end < batch_begin ||
                    next.end - batch_begin > max_batch_size) {
                    break;
                }

                batch_end = (std::max)(batch_end, next.end);
                ++last;
            }

            const auto batch_size =
                static_cast<std::size_t>(batch_end - batch_begin);
            std::vector<std::byte> buffer(batch_size);
            auto read = backend.read(Address{batch_begin}, buffer);

            if (read && *read == batch_size) {
                for (std::size_t i = cursor; i < last; ++i) {
                    const auto& item = ordered[i];
                    const auto offset =
                        static_cast<std::size_t>(item.begin - batch_begin);
                    const auto size = requests[item.index].size;
                    results[item.index].bytes.assign(
                        buffer.begin() + static_cast<std::ptrdiff_t>(offset),
                        buffer.begin() +
                            static_cast<std::ptrdiff_t>(offset + size));
                }
            } else {
                // A failed coalesced read must not hide independent successes.
                for (std::size_t i = cursor; i < last; ++i) {
                    const auto& item = ordered[i];
                    const auto& request = requests[item.index];
                    std::vector<std::byte> bytes(request.size);
                    auto individual = backend.read(request.address, bytes);

                    if (!individual) {
                        results[item.index].error = individual.error();
                        continue;
                    }
                    if (*individual != request.size) {
                        bytes.resize(*individual);
                        results[item.index].error =
                            make_error(ErrorCode::PartialTransfer,
                                       "read_scatter");
                    }
                    results[item.index].bytes = std::move(bytes);
                }
            }

            cursor = last;
        }

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "read_scatter");
    }
}

} // namespace tessera
