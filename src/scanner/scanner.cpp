#include "tessera/scanner/scanner.hpp"
#include "tessera/scanner/xref.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_backend.hpp"
#include "tessera/module/pe_image.hpp"
#include "disasm/x86_instruction_decoder.hpp"

namespace tessera {

namespace {

constexpr std::uint64_t kPageSize = 0x1000ULL;

template <class ChunkCallback>
Result<ScanStats> for_each_readable_chunk(const Process& process,
                                          AddressRange range,
                                          std::size_t overlap,
                                          const ScanOptions& options,
                                          bool& out_cancelled,
                                          ChunkCallback&& on_chunk,
                                          ScanReadPolicy read_policy = ScanReadPolicy::BestEffort,
                                          std::vector<std::byte>* workspace = nullptr) {
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
                auto total = checked_add<std::uint64_t>(
                    total_run_bytes, clipped_end - clipped_begin);
                if (!total) {
                    return fail(ErrorCode::OutOfRange, "Scanner::scan",
                                0, "Total readable scan length overflowed");
                }
                total_run_bytes = *total;
            } else {
                ++stats.regions_skipped;
                if (read_policy == ScanReadPolicy::Strict) {
                    return fail(ErrorCode::AccessDenied, "Scanner::scan",
                                0, "Strict scan encountered a filtered or inaccessible memory region");
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
                const auto want = static_cast<std::size_t>(
                    (std::min)(static_cast<std::uint64_t>(*buffer_size), rem));
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
                    if (!on_chunk(std::span<const std::byte>(buffer.data(), got),
                                  start_limit,
                                  Address{pos},
                                  stats.bytes_scanned,
                                  total_run_bytes)) {
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

} // namespace

Result<ScanResult> Scanner::scan(AddressRange range,
                                 const Pattern& pattern,
                                 const ScanOptions& options) const {
    return scan_impl(range, pattern, options, ScanReadPolicy::BestEffort, nullptr, {});
}

Result<ScanResult> Scanner::scan(AddressRange range,
                                 const Pattern& pattern,
                                 const ScanOptions& options,
                                 ScanReadPolicy read_policy) const {
    return scan_impl(range, pattern, options, read_policy, nullptr, {});
}

Result<ScanResult> Scanner::scan(AddressRange range,
                                 const Pattern& pattern,
                                 const ScanOptions& options,
                                 ScanWorkspace& workspace,
                                 ScanReadPolicy read_policy) const {
    return scan_impl(range, pattern, options, read_policy, &workspace, {});
}

Result<ScanResult> Scanner::scan_streaming(
    AddressRange range,
    const Pattern& pattern,
    const ScanOptions& options,
    FunctionRef<bool(Address)> on_match,
    ScanWorkspace* workspace,
    ScanReadPolicy read_policy) const {
    if (!on_match) {
        return fail(ErrorCode::InvalidArgument, "Scanner::scan_streaming",
                    0, "Match callback is empty");
    }
    return scan_impl(range, pattern, options, read_policy, workspace, on_match);
}

Result<ScanResult> Scanner::scan_impl(
    AddressRange range,
    const Pattern& pattern,
    const ScanOptions& options,
    ScanReadPolicy read_policy,
    ScanWorkspace* workspace,
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
            process_,
            range,
            pattern.size() - 1,
            options,
            cancelled,
            [&](std::span<const std::byte> data,
                std::size_t start_limit,
                Address chunk_base,
                std::uint64_t scanned_so_far,
                std::uint64_t total_bytes) -> bool {
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
            read_policy,
            workspace ? &workspace->buffer_ : nullptr);

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

Result<std::vector<ScanResult>> Scanner::scan_batch(
    AddressRange range,
    std::span<const Pattern> patterns,
    const ScanOptions& options) const {
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
        std::vector<ScanResult> results(patterns.size());
        const std::size_t align = options.alignment > 0 ? options.alignment : 1;
        bool cancelled = false;
        auto stats_res = for_each_readable_chunk(
            process_,
            range,
            max_pattern_len - 1,
            options,
            cancelled,
            [&](std::span<const std::byte> data,
                std::size_t start_limit,
                Address chunk_base,
                std::uint64_t scanned_so_far,
                std::uint64_t total_bytes) -> bool {
                std::size_t aggregate_hits = 0;
                bool active = false;
                for (std::size_t i = 0; i < patterns.size(); ++i) {
                    auto& result = results[i];
                    if (options.max_results > 0 && result.hits.size() >= options.max_results) {
                        continue;
                    }
                    patterns[i].search(data, start_limit, [&](std::size_t match_off) -> bool {
                        const std::uint64_t hit_addr = chunk_base.value() + match_off;
                        if (align > 1 && (hit_addr % align) != 0) {
                            return true;
                        }
                        result.hits.emplace_back(hit_addr);
                        if (options.max_results > 0 && result.hits.size() >= options.max_results) {
                            result.truncated = true;
                            return false;
                        }
                        return true;
                    });
                    if (options.max_results == 0 || result.hits.size() < options.max_results) {
                        active = true;
                    }
                    aggregate_hits += result.hits.size();
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
            });
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

Result<Address> Scanner::find_first(AddressRange range,
                                    const Pattern& pattern,
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

Result<Address> Scanner::find_unique(AddressRange range,
                                     const Pattern& pattern,
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
        return fail(ErrorCode::Ambiguous,
                    "Scanner::find_unique",
                    0,
                    "Pattern matched more than one address");
    }
    return res->hits.front();
}

namespace xref {

namespace {

template <class Predicate>
[[nodiscard]] Result<std::vector<Address>> filter_decoded_references(
    const Process& process, std::vector<Address> candidates, Predicate&& predicate) {
    std::vector<Address> verified;
    try {
        verified.reserve(candidates.size());
        for (const Address address : candidates) {
            std::array<std::byte, 15> raw{};
            auto read = memory_backend(process).read(address, raw);
            if (!read || *read == 0) {
                continue;
            }
            ::tessera::detail::x86::DecodedInstruction decoded{};
            const auto mode = process.pointer_size() == 8
                                  ? ::tessera::detail::x86::Mode::x64
                                  : ::tessera::detail::x86::Mode::x86;
            if (::tessera::detail::x86::decode_instruction(raw.data(), *read, mode, decoded) &&
                predicate(decoded)) {
                verified.push_back(address);
            }
        }
        return verified;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "xref::filter_decoded_references");
    }
}

} // namespace

Result<std::vector<Address>> find_pointer_refs(const Process& process,
                                               AddressRange range,
                                               Address target,
                                               const ScanOptions& options) {
    if (target.is_null()) {
        return fail(ErrorCode::NullAddress, "xref::find_pointer_refs");
    }
    const std::uint8_t ptr_size = process.pointer_size();
    if (ptr_size == 4 && target.value() > 0xFFFFFFFFULL) {
        return fail(ErrorCode::OutOfRange,
                    "xref::find_pointer_refs",
                    0,
                    "Target address exceeds 32-bit pointer range for x86 process");
    }

    auto pat = (ptr_size == 8)
                   ? Pattern::from_value<std::uint64_t>(target.value())
                   : Pattern::from_value<std::uint32_t>(static_cast<std::uint32_t>(target.value()));
    if (!pat) {
        return std::unexpected(pat.error());
    }

    ScanOptions ptr_opt{};
    ptr_opt.max_results = options.max_results;
    ptr_opt.alignment = (options.alignment > 1) ? options.alignment : ptr_size;
    ptr_opt.filter = options.filter;
    ptr_opt.chunk_size = options.chunk_size;
    ptr_opt.stop = options.stop;
    ptr_opt.observer = options.observer;

    Scanner scanner{process};
    auto res = scanner.scan(range, *pat, ptr_opt);
    if (!res) {
        return std::unexpected(res.error());
    }
    if (res->cancelled) {
        return fail(ErrorCode::Cancelled, "xref::find_pointer_refs");
    }
    return std::move(res->hits);
}

Result<std::vector<std::vector<Address>>> find_pointer_refs_batch(
    const Process& process,
    AddressRange range,
    std::span<const Address> targets,
    const ScanOptions& options) {
    if (targets.empty()) {
        return fail(ErrorCode::InvalidArgument, "xref::find_pointer_refs_batch",
                    0, "Target batch is empty");
    }
    const std::uint8_t pointer_size = process.pointer_size();
    std::vector<Pattern> patterns;
    try {
        patterns.reserve(targets.size());
        for (const Address target : targets) {
            if (target.is_null()) {
                return fail(ErrorCode::NullAddress, "xref::find_pointer_refs_batch");
            }
            if (pointer_size == 4 && target.value() > 0xFFFFFFFFULL) {
                return fail(ErrorCode::OutOfRange, "xref::find_pointer_refs_batch",
                            0, "Target address exceeds x86 pointer range");
            }
            auto pattern = pointer_size == 8
                               ? Pattern::from_value<std::uint64_t>(target.value())
                               : Pattern::from_value<std::uint32_t>(
                                     static_cast<std::uint32_t>(target.value()));
            if (!pattern) {
                return std::unexpected(pattern.error());
            }
            patterns.push_back(*pattern);
        }

        ScanOptions batch_options{};
        batch_options.max_results = options.max_results;
        batch_options.alignment = options.alignment > 1 ? options.alignment : pointer_size;
        batch_options.filter = options.filter;
        batch_options.chunk_size = options.chunk_size;
        batch_options.stop = options.stop;
        batch_options.observer = options.observer;
        if (options.on_progress) {
            batch_options.on_progress = [&options](const ScanProgress& progress) {
                options.on_progress(progress);
            };
        }
        Scanner scanner{process};
        auto scanned = scanner.scan_batch(range, patterns, batch_options);
        if (!scanned) {
            return std::unexpected(scanned.error());
        }
        if (std::any_of(scanned->begin(), scanned->end(),
                        [](const ScanResult& result) { return result.cancelled; })) {
            return fail(ErrorCode::Cancelled, "xref::find_pointer_refs_batch");
        }
        std::vector<std::vector<Address>> results;
        results.reserve(scanned->size());
        for (auto& result : *scanned) {
            results.push_back(std::move(result.hits));
        }
        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "xref::find_pointer_refs_batch");
    }
}

Result<std::vector<Address>> find_rel32_refs(const Process& process,
                                             AddressRange range,
                                             Address target,
                                             const Pattern& prefix,
                                             std::size_t trailing_bytes,
                                             const ScanOptions& options) {
    if (target.is_null()) {
        return fail(ErrorCode::NullAddress, "xref::find_rel32_refs");
    }
    if (prefix.empty()) {
        return fail(ErrorCode::InvalidPattern, "xref::find_rel32_refs");
    }

    auto full_pat = prefix.extended(4);
    if (!full_pat) {
        return std::unexpected(full_pat.error());
    }

    const std::size_t pre_len = prefix.size();
    const std::uint64_t tgt_val = target.value();
    std::vector<Address> out;
    std::optional<Error> arithmetic_error{};
    auto instruction_span = checked_add<std::size_t>(pre_len, sizeof(std::int32_t));
    if (!instruction_span) {
        return fail(ErrorCode::OutOfRange, "xref::find_rel32_refs", 0,
                    "Prefix and displacement length overflowed");
    }
    instruction_span = checked_add<std::size_t>(*instruction_span, trailing_bytes);
    if (!instruction_span) {
        return fail(ErrorCode::OutOfRange, "xref::find_rel32_refs", 0,
                    "Instruction length plus trailing bytes overflowed");
    }

    try {
        bool cancelled = false;
        auto stats_res = for_each_readable_chunk(
            process,
            range,
            full_pat->size() - 1,
            options,
            cancelled,
            [&](std::span<const std::byte> data,
                std::size_t start_limit,
                Address chunk_base,
                std::uint64_t,
                std::uint64_t) -> bool {
                bool more = true;
                full_pat->search(data, start_limit, [&](std::size_t off) -> bool {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, data.data() + off + pre_len, sizeof(disp));
                    const std::uint64_t ins_addr = chunk_base.value() + off;
                    auto next_ip = checked_add<std::uint64_t>(
                        ins_addr, static_cast<std::uint64_t>(*instruction_span));
                    if (!next_ip) {
                        arithmetic_error = next_ip.error();
                        more = false;
                        return false;
                    }
                    auto resolved = checked_offset<std::uint64_t>(*next_ip, disp);
                    if (resolved && *resolved == tgt_val) {
                        out.emplace_back(ins_addr);
                        if (options.max_results > 0 && out.size() >= options.max_results) {
                            more = false;
                            return false;
                        }
                    }
                    return true;
                });
                return more;
            });

        if (!stats_res) {
            return std::unexpected(stats_res.error());
        }
        if (arithmetic_error) {
            return std::unexpected(*arithmetic_error);
        }
        if (cancelled) {
            return fail(ErrorCode::Cancelled, "xref::find_rel32_refs");
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "xref::find_rel32_refs");
    }
}

Result<std::vector<Address>> find_calls(const Process& process,
                                        AddressRange range,
                                        Address target,
                                        const ScanOptions& options) {
    static constexpr std::array<std::byte, 1> kCallOpcode{std::byte{0xE8}};
    auto pat = Pattern::from_bytes(kCallOpcode);
    if (!pat) {
        return std::unexpected(pat.error());
    }
    auto candidates = find_rel32_refs(process, range, target, *pat, 0, options);
    if (!candidates) {
        return std::unexpected(candidates.error());
    }
    return filter_decoded_references(
        process, std::move(*candidates),
        [](const ::tessera::detail::x86::DecodedInstruction& decoded) {
            return decoded.opcode == 0xE8u && decoded.has_relative_operand &&
                   decoded.relative_size == 4;
        });
}

Result<std::vector<Address>> find_jumps(const Process& process,
                                        AddressRange range,
                                        Address target,
                                        const ScanOptions& options) {
    static constexpr std::array<std::byte, 1> kJmpOpcode{std::byte{0xE9}};
    auto pat = Pattern::from_bytes(kJmpOpcode);
    if (!pat) {
        return std::unexpected(pat.error());
    }
    auto candidates = find_rel32_refs(process, range, target, *pat, 0, options);
    if (!candidates) {
        return std::unexpected(candidates.error());
    }
    return filter_decoded_references(
        process, std::move(*candidates),
        [](const ::tessera::detail::x86::DecodedInstruction& decoded) {
            return decoded.opcode == 0xE9u && decoded.has_relative_operand &&
                   decoded.relative_size == 4;
        });
}

Result<std::vector<Address>> find_conditional_branches(
    const Process& process, AddressRange range, Address target,
    const ScanOptions& options) {
    auto prefix = Pattern::parse("0F 8?");
    if (!prefix) {
        return std::unexpected(prefix.error());
    }
    auto candidates = find_rel32_refs(process, range, target, *prefix, 0, options);
    if (!candidates) {
        return std::unexpected(candidates.error());
    }
    return filter_decoded_references(
        process, std::move(*candidates),
        [](const ::tessera::detail::x86::DecodedInstruction& decoded) {
            return decoded.opcode == 0x0Fu && decoded.opcode2 >= 0x80u &&
                   decoded.opcode2 <= 0x8Fu && decoded.has_relative_operand &&
                   decoded.relative_size == 4;
        });
}

Result<std::vector<Address>> find_indirect_refs(
    const Process& process, AddressRange range, Address target,
    const ScanOptions& options) {
    if (target.is_null()) {
        return fail(ErrorCode::NullAddress, "xref::find_indirect_refs");
    }
    try {
        auto call_pattern = Pattern::parse("FF 1? ?? ?? ?? ??");
        auto jump_pattern = Pattern::parse("FF 2? ?? ?? ?? ??");
        if (!call_pattern || !jump_pattern) {
            return fail(ErrorCode::InvalidPattern, "xref::find_indirect_refs");
        }
        Scanner scanner{process};
        std::vector<Address> references;
        const std::array<Pattern, 2> patterns{*call_pattern, *jump_pattern};
        for (const auto& pattern : patterns) {
            auto matches = scanner.scan(range, pattern, options);
            if (!matches) {
                return std::unexpected(matches.error());
            }
            if (matches->cancelled) {
                return fail(ErrorCode::Cancelled, "xref::find_indirect_refs");
            }
            for (const Address instruction : matches->hits) {
                std::array<std::byte, 15> raw{};
                auto read = memory_backend(process).read(instruction, raw);
                if (!read || *read < 6) {
                    continue;
                }
                ::tessera::detail::x86::DecodedInstruction decoded{};
                const auto mode = process.pointer_size() == 8
                                      ? ::tessera::detail::x86::Mode::x64
                                      : ::tessera::detail::x86::Mode::x86;
                if (!::tessera::detail::x86::decode_instruction(
                        raw.data(), *read, mode, decoded) ||
                    decoded.opcode != 0xFFu ||
                    (decoded.modrm_reg != 2u && decoded.modrm_reg != 4u) ||
                    decoded.length != 6) {
                    continue;
                }

                std::int32_t displacement = 0;
                std::memcpy(&displacement, raw.data() + 2, sizeof(displacement));
                std::uint64_t slot = 0;
                if (process.pointer_size() == 8) {
                    if (!decoded.has_rip_relative_operand) {
                        continue;
                    }
                    auto next_ip = checked_add<std::uint64_t>(
                        instruction.value(), static_cast<std::uint64_t>(decoded.length));
                    if (!next_ip) {
                        continue;
                    }
                    auto slot_address = checked_offset<std::uint64_t>(*next_ip, displacement);
                    if (!slot_address) {
                        continue;
                    }
                    slot = *slot_address;
                } else {
                    slot = static_cast<std::uint32_t>(displacement);
                }

                std::array<std::byte, sizeof(std::uint64_t)> pointer_bytes{};
                const std::size_t pointer_size = process.pointer_size();
                auto pointer_read = memory_backend(process).read(
                    Address{slot}, std::span<std::byte>{pointer_bytes}.first(pointer_size));
                if (!pointer_read || *pointer_read != pointer_size) {
                    continue;
                }
                std::uint64_t resolved = 0;
                if (pointer_size == 8) {
                    std::memcpy(&resolved, pointer_bytes.data(), sizeof(std::uint64_t));
                } else {
                    std::uint32_t pointer32 = 0;
                    std::memcpy(&pointer32, pointer_bytes.data(), sizeof(pointer32));
                    resolved = pointer32;
                }
                if (resolved == target.value()) {
                    references.push_back(instruction);
                    if (options.max_results > 0 && references.size() >= options.max_results) {
                        break;
                    }
                }
            }
            if (options.max_results > 0 && references.size() >= options.max_results) {
                break;
            }
        }
        std::sort(references.begin(), references.end());
        references.erase(std::unique(references.begin(), references.end()), references.end());
        return references;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "xref::find_indirect_refs");
    }
}

Result<std::vector<Address>> find_relocated_pointer_refs(
    const Process& process, Address module_base, const PeImage& image, Address target) {
    if (module_base.is_null() || target.is_null()) {
        return fail(ErrorCode::NullAddress, "xref::find_relocated_pointer_refs");
    }
    const std::size_t pointer_size = image.kind() == PeKind::Pe32Plus ? 8u : 4u;
    if (process.pointer_size() != pointer_size) {
        return fail(ErrorCode::UnsupportedArchitecture, "xref::find_relocated_pointer_refs",
                    0, "Process and PE image architectures do not match");
    }
    try {
        std::vector<Address> references;
        for (const auto& relocation : image.relocations()) {
            const bool pointer_relocation =
                (pointer_size == 4u && relocation.type == 3u) ||
                (pointer_size == 8u && relocation.type == 10u);
            if (!pointer_relocation) {
                continue;
            }
            auto location = module_base.add_rva(relocation.location);
            if (!location) {
                return std::unexpected(location.error());
            }
            std::array<std::byte, sizeof(std::uint64_t)> raw{};
            auto read = memory_backend(process).read(
                *location, std::span<std::byte>{raw}.first(pointer_size));
            if (!read || *read != pointer_size) {
                continue;
            }
            std::uint64_t value = 0;
            if (pointer_size == 8u) {
                std::memcpy(&value, raw.data(), sizeof(value));
            } else {
                std::uint32_t value32 = 0;
                std::memcpy(&value32, raw.data(), sizeof(value32));
                value = value32;
            }
            if (value == target.value()) {
                references.push_back(*location);
            }
        }
        std::sort(references.begin(), references.end());
        references.erase(std::unique(references.begin(), references.end()), references.end());
        return references;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "xref::find_relocated_pointer_refs");
    }
}

} // namespace xref

} // namespace tessera
