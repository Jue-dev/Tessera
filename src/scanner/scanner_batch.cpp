#include "scanner_detail.hpp"
#include "tessera/scanner/scanner.hpp"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <new>
namespace tessera {
using scanner_detail::for_each_readable_chunk;
Result<std::vector<ScanResult>> Scanner::scan_batch(AddressRange range, std::span<const Pattern> patterns,
                                                    const ScanOptions& options) const {
    return scan_batch_impl(range, patterns, options, nullptr);
}

Result<std::vector<ScanResult>> Scanner::scan_batch(AddressRange range, std::span<const Pattern> patterns,
                                                    const ScanOptions& options,
                                                    ScanWorkspace& workspace) const {
    return scan_batch_impl(range, patterns, options, &workspace);
}

Result<std::vector<ScanResult>> Scanner::scan_batch_impl(AddressRange range,
                                                         std::span<const Pattern> patterns,
                                                         const ScanOptions& options,
                                                         ScanWorkspace* workspace) const {
    if (range.empty()) {
        return fail(ErrorCode::InvalidArgument, "Scanner::scan_batch", 0, "AddressRange is empty");
    }
    if (patterns.empty()) {
        return fail(ErrorCode::InvalidArgument, "Scanner::scan_batch", 0, "Pattern batch is empty");
    }

    std::size_t max_pattern_len = 0;
    for (const auto& pattern : patterns) {
        if (pattern.empty()) {
            return fail(ErrorCode::InvalidPattern, "Scanner::scan_batch", 0,
                        "Pattern batch contains an empty pattern");
        }
        max_pattern_len = (std::max)(max_pattern_len, pattern.size());
    }

    try {
        struct AnchorGroup {
            std::size_t anchor_index = 0;
            std::byte anchor_value{};
            std::vector<std::size_t> pattern_indices{};
        };
        std::vector<AnchorGroup> groups;
        std::vector<std::size_t> anchorless;
        groups.reserve(patterns.size());
        anchorless.reserve(patterns.size());
        for (std::size_t i = 0; i < patterns.size(); ++i) {
            const auto anchor = patterns[i].anchor_index();
            if (!anchor) {
                anchorless.push_back(i);
                continue;
            }
            const std::byte value = patterns[i].bytes()[*anchor];
            auto group = std::find_if(groups.begin(), groups.end(), [&](const AnchorGroup& item) {
                return item.anchor_index == *anchor && item.anchor_value == value;
            });
            if (group == groups.end()) {
                groups.push_back(AnchorGroup{.anchor_index = *anchor, .anchor_value = value});
                group = std::prev(groups.end());
            }
            group->pattern_indices.push_back(i);
        }

        std::vector<ScanResult> results(patterns.size());
        const std::size_t align = options.alignment > 0 ? options.alignment : 1;
        bool cancelled = false;
        auto stats_res = for_each_readable_chunk(
            process_, range, max_pattern_len - 1, options, cancelled,
            [&](std::span<const std::byte> data, std::size_t start_limit, Address chunk_base,
                std::uint64_t scanned_so_far, std::uint64_t total_bytes) -> bool {
                std::size_t aggregate_hits = 0;
                bool active = false;
                const auto quota_reached = [&](std::size_t index) {
                    return options.max_results > 0 && results[index].hits.size() >= options.max_results;
                };

                for (const auto& group : groups) {
                    bool group_active = false;
                    for (const std::size_t index : group.pattern_indices) {
                        group_active = group_active || !quota_reached(index);
                    }
                    if (!group_active || group.anchor_index >= data.size()) {
                        continue;
                    }

                    std::size_t offset = 0;
                    while (offset < start_limit && group.anchor_index < data.size() - offset) {
                        const std::size_t search_length =
                            (std::min)(start_limit - offset, data.size() - offset - group.anchor_index);
                        if (search_length == 0) {
                            break;
                        }
                        const auto* found = static_cast<const std::byte*>(
                            std::memchr(data.data() + offset + group.anchor_index,
                                        std::to_integer<unsigned char>(group.anchor_value), search_length));
                        if (found == nullptr) {
                            break;
                        }
                        const std::size_t anchor_position = static_cast<std::size_t>(found - data.data());
                        const std::size_t candidate = anchor_position - group.anchor_index;
                        for (const std::size_t index : group.pattern_indices) {
                            if (quota_reached(index) || !patterns[index].matches(data.subspan(candidate))) {
                                continue;
                            }
                            const std::uint64_t hit_address = chunk_base.value() + candidate;
                            if (align > 1 && (hit_address % align) != 0) {
                                continue;
                            }
                            auto& result = results[index];
                            result.hits.emplace_back(hit_address);
                            ++aggregate_hits;
                            if (quota_reached(index)) {
                                result.truncated = true;
                            }
                        }
                        offset = candidate + 1;
                    }
                    for (const std::size_t index : group.pattern_indices) {
                        active = active || !quota_reached(index);
                    }
                }

                for (const std::size_t index : anchorless) {
                    auto& result = results[index];
                    if (quota_reached(index)) {
                        continue;
                    }
                    patterns[index].search(data, start_limit, [&](std::size_t match_off) -> bool {
                        const std::uint64_t hit_address = chunk_base.value() + match_off;
                        if (align > 1 && (hit_address % align) != 0) {
                            return true;
                        }
                        result.hits.emplace_back(hit_address);
                        ++aggregate_hits;
                        if (quota_reached(index)) {
                            result.truncated = true;
                            return false;
                        }
                        return true;
                    });
                    active = active || !quota_reached(index);
                }

                if (options.on_progress) {
                    const ScanProgress progress{
                        .bytes_scanned = scanned_so_far,
                        .total_bytes = total_bytes,
                        .hits_found = aggregate_hits,
                    };
                    options.on_progress(progress);
                }
                return active;
            },
            ScanReadPolicy::BestEffort, workspace ? &workspace->buffer_ : nullptr);
        if (!stats_res) {
            return std::unexpected(stats_res.error());
        }
        for (auto& result : results) {
            result.stats = *stats_res;
            result.cancelled = cancelled;
        }
        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Scanner::scan_batch");
    }
}

} // namespace tessera
