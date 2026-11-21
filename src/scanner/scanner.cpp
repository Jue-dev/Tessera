#include "tessera/scanner/scanner.hpp"

#include "scanner_detail.hpp"
#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_backend.hpp"

#include <algorithm>
#include <new>
#include <utility>
namespace tessera::scanner_detail {
namespace {
constexpr std::uint64_t kPageSize = 0x1000ULL;
}

Result<ScanStats> for_each_readable_chunk(
    const Process& process, AddressRange range, std::size_t overlap, const ScanOptions& options,
    bool& out_cancelled,
    FunctionRef<bool(std::span<const std::byte>, std::size_t, Address, std::uint64_t, std::uint64_t)>
        on_chunk,
    ScanReadPolicy read_policy, std::vector<std::byte>* workspace) {
    out_cancelled = false;
    if (range.empty()) {
        return fail(ErrorCode::InvalidArgument, "Scanner::scan", 0, "Scan range is empty");
    }

    auto range_end_res = range.end();
    if (!range_end_res) {
        return std::unexpected(range_end_res.error());
    }

    const std::uint64_t max_app = process.info().max_application_address;
    auto max_app_exclusive = checked_add<std::uint64_t>(max_app, 1u);
    if (!max_app_exclusive) {
        return fail(ErrorCode::OutOfRange, "Scanner::scan", 0,
                    "Maximum application address cannot be represented as an exclusive limit");
    }
    const std::uint64_t scan_begin = range.begin().value();
    const std::uint64_t scan_end = (std::min)(range_end_res->value(), *max_app_exclusive);
    if (scan_begin >= scan_end) {
        return ScanStats{};
    }

    const std::size_t chunk_sz = (std::max)(options.chunk_size, std::size_t{4096});
    const IMemoryBackend& backend = memory_backend(process);

    ScanStats stats{};
    struct ContiguousRun {
        std::uint64_t begin;
        std::uint64_t end;
    };

    std::vector<ContiguousRun> runs;
    std::uint64_t total_run_bytes = 0;

    try {
        std::uint64_t cur = scan_begin;
        while (cur < scan_end) {
            if (options.stop.stop_requested()) {
                out_cancelled = true;
                return stats;
            }
            auto q = backend.query(Address{cur});
            if (!q) {
                return std::unexpected(q.error());
            }
            auto r_end_res = checked_add<std::uint64_t>(q->base.value(), q->size);
            if (!r_end_res || *r_end_res <= cur) {
                return fail(ErrorCode::OutOfRange, "Scanner::scan", 0,
                            "Memory-region query returned an invalid or non-progressing range");
            }
            const std::uint64_t r_end = *r_end_res;
            const std::uint64_t clipped_begin = (std::max)(cur, q->base.value());
            const std::uint64_t clipped_end = (std::min)(r_end, scan_end);

            if (clipped_begin < clipped_end && matches_region_filter(*q, options.filter)) {
                ++stats.regions_scanned;
                if (!runs.empty() && runs.back().end == clipped_begin) {
                    runs.back().end = clipped_end;
                } else {
                    runs.push_back(ContiguousRun{clipped_begin, clipped_end});
                }
                auto total = checked_add<std::uint64_t>(total_run_bytes, clipped_end - clipped_begin);
                if (!total) {
                    return fail(ErrorCode::OutOfRange, "Scanner::scan", 0,
                                "Total readable scan length overflowed");
                }
                total_run_bytes = *total;
            } else {
                ++stats.regions_skipped;
                if (read_policy == ScanReadPolicy::Strict) {
                    return fail(ErrorCode::AccessDenied, "Scanner::scan", 0,
                                "Strict scan encountered a filtered or inaccessible memory region");
                }
            }
            cur = r_end;
        }

        auto buffer_size = checked_add<std::size_t>(chunk_sz, overlap);
        if (!buffer_size) {
            return fail(ErrorCode::OutOfRange, "Scanner::scan", 0,
                        "Chunk size plus pattern overlap overflowed");
        }
        std::vector<std::byte> local_buffer;
        std::vector<std::byte>& buffer = workspace ? *workspace : local_buffer;
        buffer.resize(*buffer_size);
        bool keep_going = true;

        for (const auto& run : runs) {
            if (!keep_going) {
                break;
            }
            std::uint64_t pos = run.begin;
            while (pos < run.end && keep_going) {
                if (options.stop.stop_requested()) {
                    out_cancelled = true;
                    return stats;
                }

                const std::uint64_t rem = run.end - pos;
                const auto want =
                    static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(*buffer_size), rem));
                const bool is_last_in_run = (want == rem);

                auto got_res = backend.read(Address{pos}, std::span<std::byte>(buffer.data(), want));
                const std::size_t got = got_res ? *got_res : 0;
                const bool full_ok = got_res.has_value() && (got == want);

                if (!full_ok) {
                    ++stats.read_errors;
                    if (read_policy == ScanReadPolicy::Strict) {
                        return fail(ErrorCode::PartialTransfer, "Scanner::scan",
                                    got_res ? 0 : got_res.error().native,
                                    "Strict scan encountered a partial or failed memory read");
                    }
                }

                if (got > 0) {
                    const std::size_t valid_Advance =
                        (is_last_in_run || !full_ok) ? got : (std::min)(chunk_sz, got);
                    stats.bytes_scanned += valid_Advance;
                    const std::size_t start_limit = (is_last_in_run || !full_ok) ? got : chunk_sz;
                    if (!on_chunk(std::span<const std::byte>(buffer.data(), got), start_limit, Address{pos},
                                  stats.bytes_scanned, total_run_bytes)) {
                        keep_going = false;
                        break;
                    }
                }

                if (full_ok) {
                    if (is_last_in_run) {
                        break;
                    }
                    pos += chunk_sz;
                } else {
                    const std::uint64_t fail_at = pos + got;
                    const std::uint64_t next_page = (fail_at & ~(kPageSize - 1ULL)) + kPageSize;
                    if (next_page <= pos) {
                        break;
                    }
                    pos = next_page;
                }
            }
        }
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Scanner::scan");
    }

    return stats;
}

} // namespace tessera::scanner_detail
namespace tessera {
using scanner_detail::for_each_readable_chunk;
Result<ScanResult> Scanner::scan(AddressRange range, const Pattern& pattern,
                                 const ScanOptions& options) const {
    return scan_impl(range, pattern, options, ScanReadPolicy::BestEffort, nullptr, {});
}

Result<ScanResult> Scanner::scan(AddressRange range, const Pattern& pattern, const ScanOptions& options,
                                 ScanReadPolicy read_policy) const {
    return scan_impl(range, pattern, options, read_policy, nullptr, {});
}

Result<ScanResult> Scanner::scan(AddressRange range, const Pattern& pattern, const ScanOptions& options,
                                 ScanWorkspace& workspace, ScanReadPolicy read_policy) const {
    return scan_impl(range, pattern, options, read_policy, &workspace, {});
}

Result<ScanResult> Scanner::scan_streaming(AddressRange range, const Pattern& pattern,
                                           const ScanOptions& options, FunctionRef<bool(Address)> on_match,
                                           ScanWorkspace* workspace, ScanReadPolicy read_policy) const {
    if (!on_match) {
        return fail(ErrorCode::InvalidArgument, "Scanner::scan_streaming", 0, "Match callback is empty");
    }
    return scan_impl(range, pattern, options, read_policy, workspace, on_match);
}

Result<ScanResult> Scanner::scan_impl(AddressRange range, const Pattern& pattern, const ScanOptions& options,
                                      ScanReadPolicy read_policy, ScanWorkspace* workspace,
                                      FunctionRef<bool(Address)> on_match) const {
    if (pattern.empty()) {
        return fail(ErrorCode::InvalidPattern, "Scanner::scan", 0, "Pattern is empty");
    }
    if (range.empty()) {
        return fail(ErrorCode::InvalidArgument, "Scanner::scan", 0, "AddressRange is empty");
    }

    DiagnosticObserver* obs = options.observer ? options.observer : process_.observer();
    diagnostics::notify(obs, DiagnosticSeverity::Info, "Scanner", "Scan started");

    ScanResult result{};
    std::size_t matches_seen = 0;
    const std::size_t align = options.alignment > 0 ? options.alignment : 1;

    try {
        bool cancelled = false;
        auto stats_res = for_each_readable_chunk(
            process_, range, pattern.size() - 1, options, cancelled,
            [&](std::span<const std::byte> data, std::size_t start_limit, Address chunk_base,
                std::uint64_t scanned_so_far, std::uint64_t total_bytes) -> bool {
                bool continue_scan = true;
                pattern.search(data, start_limit, [&](std::size_t match_off) -> bool {
                    const std::uint64_t hit_addr = chunk_base.value() + match_off;
                    if (align > 1 && (hit_addr % align) != 0) {
                        return true;
                    }
                    const Address hit{hit_addr};
                    ++matches_seen;
                    if (!on_match) {
                        result.hits.emplace_back(hit);
                    }
                    if (on_match && !on_match(hit)) {
                        result.cancelled = true;
                        continue_scan = false;
                        return false;
                    }
                    if (options.max_results > 0 && matches_seen >= options.max_results) {
                        result.truncated = true;
                        continue_scan = false;
                        return false;
                    }
                    return true;
                });

                if (options.on_progress) {
                    const ScanProgress prog{
                        .bytes_scanned = scanned_so_far,
                        .total_bytes = total_bytes,
                        .hits_found = matches_seen,
                    };
                    options.on_progress(prog);
                }
                return continue_scan;
            },
            read_policy, workspace ? &workspace->buffer_ : nullptr);

        if (!stats_res) {
            return std::unexpected(stats_res.error());
        }
        result.stats = *stats_res;
        result.cancelled = result.cancelled || cancelled;
        return result;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Scanner::scan");
    }
}

Result<Address> Scanner::find_first(AddressRange range, const Pattern& pattern,
                                    const ScanOptions& options) const {
    ScanOptions first_opt{};
    first_opt.max_results = 1;
    first_opt.alignment = options.alignment;
    first_opt.filter = options.filter;
    first_opt.chunk_size = options.chunk_size;
    first_opt.stop = options.stop;
    first_opt.observer = options.observer;

    auto res = scan(range, pattern, first_opt);
    if (!res) {
        return std::unexpected(res.error());
    }
    if (res->cancelled) {
        return fail(ErrorCode::Cancelled, "Scanner::find_first");
    }
    if (res->hits.empty()) {
        return fail(ErrorCode::NotFound, "Scanner::find_first");
    }
    return res->hits.front();
}

Result<Address> Scanner::find_unique(AddressRange range, const Pattern& pattern,
                                     const ScanOptions& options) const {
    ScanOptions unique_opt{};
    unique_opt.max_results = 2;
    unique_opt.alignment = options.alignment;
    unique_opt.filter = options.filter;
    unique_opt.chunk_size = options.chunk_size;
    unique_opt.stop = options.stop;
    unique_opt.observer = options.observer;

    auto res = scan(range, pattern, unique_opt);
    if (!res) {
        return std::unexpected(res.error());
    }
    if (res->cancelled) {
        return fail(ErrorCode::Cancelled, "Scanner::find_unique");
    }
    if (res->hits.empty()) {
        return fail(ErrorCode::NotFound, "Scanner::find_unique");
    }
    if (res->hits.size() > 1) {
        return fail(ErrorCode::Ambiguous, "Scanner::find_unique", 0, "Pattern matched more than one address");
    }
    return res->hits.front();
}

} // namespace tessera
