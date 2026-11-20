#include "tessera/memory/memory.hpp"

#include <algorithm>
#include <cstring>
#include <new>

#include "tessera/core/assert.hpp"
#include "tessera/core/checked_math.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"

namespace tessera {

namespace {
constexpr std::uint64_t kPageSize = 0x1000ULL;
} // namespace

Result<std::vector<MemoryRegionInfo>> enumerate_regions(const Process& process,
                                                        AddressRange bounds,
                                                        RegionFilter filter) {
    const std::uint64_t max_addr = process.info().max_application_address;
    std::uint64_t cur = bounds.empty() ? 0ULL : bounds.begin().value();
    auto max_exclusive = checked_add<std::uint64_t>(max_addr, 1u);
    if (!max_exclusive) {
        return fail(ErrorCode::OutOfRange, "enumerate_regions", 0,
                    "Maximum application address cannot be represented as an exclusive limit");
    }
    std::uint64_t limit = *max_exclusive;
    if (!bounds.empty()) {
        auto end_res = bounds.end();
        if (!end_res) {
            return std::unexpected(end_res.error());
        }
        limit = (std::min)(end_res->value(), *max_exclusive);
    }

    const IMemoryBackend& backend = memory_backend(process);
    std::vector<MemoryRegionInfo> regions;
    try {
        while (cur < limit) {
            auto reg_res = backend.query(Address{cur});
            if (!reg_res) {
                // An unbounded walk ends naturally when the backend reaches the
                // target's highest queryable address (VirtualQueryEx reports
                // ERROR_INVALID_PARAMETER there). Explicit bounded queries must
                // still surface an out-of-range request to the caller.
                if (bounds.empty() && reg_res.error().code == ErrorCode::OutOfRange) {
                    break;
                }
                return std::unexpected(reg_res.error());
            }
            const MemoryRegionInfo& reg = *reg_res;
            auto reg_end = checked_add<std::uint64_t>(reg.base.value(), reg.size);
            if (!reg_end || *reg_end <= cur) {
                return fail(ErrorCode::OutOfRange, "enumerate_regions", 0,
                            "Memory-region query returned an invalid or non-progressing range");
            }
            if (matches_region_filter(reg, filter)) {
                regions.push_back(reg);
            } else {
                diagnostics::notify(process.observer(),
                                    DiagnosticSeverity::Info,
                                    "Memory",
                                    "Region skipped by filter");
            }
            cur = *reg_end;
        }
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "enumerate_regions");
    }
    return regions;
}

std::vector<AddressRange> merge_contiguous_regions(std::span<const MemoryRegionInfo> regions,
                                                   AddressRange clip_bounds) {
    std::vector<AddressRange> merged;
    const bool has_clip = !clip_bounds.empty();
    const std::uint64_t clip_begin = has_clip ? clip_bounds.begin().value() : 0ULL;
    const std::uint64_t clip_end =
        has_clip ? clip_bounds.end().value_or(Address{0}).value() : 0ULL;

    for (const auto& reg : regions) {
        std::uint64_t r_begin = reg.base.value();
        auto r_end_res = reg.range().end();
        if (!r_end_res) {
            continue;
        }
        std::uint64_t r_end = r_end_res->value();
        if (has_clip) {
            r_begin = (std::max)(r_begin, clip_begin);
            r_end = (std::min)(r_end, clip_end);
        }
        if (r_begin >= r_end) {
            continue;
        }
        const std::uint64_t r_size = r_end - r_begin;
        if (!merged.empty()) {
            auto prev_end = merged.back().end();
            if (prev_end && prev_end->value() == r_begin) {
                merged.back() = AddressRange{merged.back().begin(), merged.back().size() + r_size};
                continue;
            }
        }
        merged.emplace_back(Address{r_begin}, r_size);
    }
    return merged;
}

// ---- MemoryReader -----------------------------------------------------------

Status MemoryReader::read_exact(Address address, std::span<std::byte> buffer) const noexcept {
    if (buffer.empty()) {
        return ok();
    }
    if (address.is_null()) {
        return fail(ErrorCode::NullAddress, "MemoryReader::read_exact");
    }
    if (!checked_add<std::uint64_t>(address.value(), static_cast<std::uint64_t>(buffer.size()))) {
        return fail(ErrorCode::AddressOverflow, "MemoryReader::read_exact");
    }

    auto got = memory_backend(process_).read(address, buffer);
    if (!got) {
        return std::unexpected(got.error());
    }
    if (*got != buffer.size()) {
        return fail(ErrorCode::PartialTransfer,
                    "MemoryReader::read_exact",
                    0,
                    "Read fewer bytes than requested");
    }
    return ok();
}

Result<std::size_t> MemoryReader::read_partial(Address address,
                                               std::span<std::byte> buffer) const noexcept {
    if (buffer.empty()) {
        return std::size_t{0};
    }
    if (address.is_null()) {
        return fail(ErrorCode::NullAddress, "MemoryReader::read_partial");
    }
    return memory_backend(process_).read(address, buffer);
}

Result<std::vector<std::byte>> MemoryReader::read_bytes(Address address,
                                                        std::size_t count,
                                                        ReadLimits limits) const {
    if (address.is_null()) {
        return fail(ErrorCode::NullAddress, "MemoryReader::read_bytes");
    }
    if (count > limits.max_bytes) {
        return fail(ErrorCode::OutOfRange,
                    "MemoryReader::read_bytes",
                    0,
                    "Requested byte count exceeds ReadLimits::max_bytes");
    }
    if (count == 0) {
        return std::vector<std::byte>{};
    }
    if (!checked_add<std::uint64_t>(address.value(), static_cast<std::uint64_t>(count))) {
        return fail(ErrorCode::AddressOverflow, "MemoryReader::read_bytes");
    }

    // For large allocations (> 1 MiB), verify readability first to avoid allocating megabytes for unreadable ranges
    if (count > (1ULL << 20)) {
        auto readable = is_readable(AddressRange{address, static_cast<std::uint64_t>(count)});
        if (!readable || !*readable) {
            return fail(ErrorCode::AccessDenied,
                        "MemoryReader::read_bytes",
                        0,
                        "Range is not fully readable");
        }
    }

    try {
        std::vector<std::byte> out(count);
        auto st = read_exact(address, out);
        if (!st) {
            return std::unexpected(st.error());
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "MemoryReader::read_bytes");
    }
}

Result<Address> MemoryReader::read_pointer(Address address) const noexcept {
    if (process_.pointer_size() == 8) {
        auto val = read<std::uint64_t>(address);
        if (!val) {
            return std::unexpected(val.error());
        }
        return Address{*val};
    }
    auto val = read<std::uint32_t>(address);
    if (!val) {
        return std::unexpected(val.error());
    }
    return Address{static_cast<std::uint64_t>(*val)};
}

namespace {

template <class CharT>
Result<std::basic_string<CharT>> read_terminated_string(const Process& process,
                                                        Address address,
                                                        std::size_t max_chars,
                                                        std::string_view op_name) {
    if (address.is_null()) {
        return fail(ErrorCode::NullAddress, op_name);
    }
    if (max_chars == 0) {
        return std::basic_string<CharT>{};
    }

    const IMemoryBackend& backend = memory_backend(process);
    try {
        std::basic_string<CharT> out;
        std::array<CharT, 128> chunk{};
        std::uint64_t cur = address.value();
        bool any_read = false;

        while (out.size() < max_chars) {
            const std::uint64_t page_rem_bytes = kPageSize - (cur & (kPageSize - 1ULL));
            const std::size_t chars_to_page =
                (std::max)(std::size_t{1}, static_cast<std::size_t>(page_rem_bytes / sizeof(CharT)));
            const std::size_t want_chars =
                (std::min)({chunk.size(), max_chars - out.size(), chars_to_page});
            const std::size_t want_bytes = want_chars * sizeof(CharT);

            auto got_res = backend.read(
                Address{cur},
                std::span<std::byte>(reinterpret_cast<std::byte*>(chunk.data()), want_bytes));
            if (!got_res || *got_res < sizeof(CharT)) {
                if (!any_read && !got_res) {
                    return std::unexpected(got_res.error());
                }
                break;
            }

            const std::size_t got_chars = *got_res / sizeof(CharT);
            any_read = true;
            for (std::size_t i = 0; i < got_chars; ++i) {
                if (chunk[i] == CharT{0}) {
                    return out;
                }
                out.push_back(chunk[i]);
            }

            if (*got_res < want_bytes) {
                break;
            }
            auto next = checked_add<std::uint64_t>(cur, static_cast<std::uint64_t>(want_bytes));
            if (!next) {
                break;
            }
            cur = *next;
        }

        if (!any_read) {
            return fail(ErrorCode::PartialTransfer, op_name, 0, "Zero characters could be read");
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, op_name);
    }
}

template <class Pred>
Result<bool> check_all_pages(const Process& process, AddressRange range, Pred&& pred) noexcept {
    if (range.empty()) {
        return false;
    }
    auto end_res = range.end();
    if (!end_res) {
        return std::unexpected(end_res.error());
    }
    const std::uint64_t end = end_res->value();
    std::uint64_t cur = range.begin().value();
    const IMemoryBackend& backend = memory_backend(process);

    while (cur < end) {
        auto q = backend.query(Address{cur});
        if (!q) {
            return false;
        }
        if (!pred(*q)) {
            return false;
        }
        auto next = checked_add<std::uint64_t>(q->base.value(), q->size);
        if (!next || *next <= cur) {
            return false;
        }
        cur = *next;
    }
    return true;
}

} // namespace

Result<std::string> MemoryReader::read_cstring(Address address, std::size_t max_chars) const {
    return read_terminated_string<char>(process_, address, max_chars, "MemoryReader::read_cstring");
}

Result<std::u16string> MemoryReader::read_utf16(Address address, std::size_t max_chars) const {
    return read_terminated_string<char16_t>(process_, address, max_chars, "MemoryReader::read_utf16");
}

Result<MemoryRegionInfo> MemoryReader::query(Address address) const noexcept {
    return memory_backend(process_).query(address);
}

Result<bool> MemoryReader::is_readable(AddressRange range) const noexcept {
    return check_all_pages(process_, range, [](const MemoryRegionInfo& m) { return m.is_readable(); });
}

Result<bool> MemoryReader::is_writable(AddressRange range) const noexcept {
    return check_all_pages(process_, range, [](const MemoryRegionInfo& m) { return m.is_writable(); });
}

Result<bool> MemoryReader::is_executable(AddressRange range) const noexcept {
    return check_all_pages(process_, range, [](const MemoryRegionInfo& m) { return m.is_executable(); });
}

// ---- MemoryWriter -----------------------------------------------------------

Status MemoryWriter::restore_pending_protections(WriteReport& report) const {
    const IMemoryBackend& backend = memory_backend(process_);
    std::optional<Error> first_error;
    auto it = report.pending_protection_restores.begin();
    while (it != report.pending_protection_restores.end()) {
        auto restored = backend.protect(
            it->range.begin(), it->range.size(), it->original_protection);
        if (restored) {
            it = report.pending_protection_restores.erase(it);
            continue;
        }
        if (!first_error) {
            first_error = make_error(
                ErrorCode::ProtectionRestoreFailed,
                restored.error().operation,
                restored.error().native,
                "Retrying a pending page-protection restoration failed");
        }
        ++it;
    }
    if (first_error) {
        return std::unexpected(*first_error);
    }
    report.protection_restore_warning.reset();
    return ok();
}

Result<WriteReport> MemoryWriter::write_with_report(Address address,
                                                    std::span<const std::byte> data,
                                                    WriteOptions options) const {
    if (address.is_null()) {
        return fail(ErrorCode::NullAddress, "MemoryWriter::write_with_report");
    }
    if (data.empty()) {
        return WriteReport{};
    }

    const AddressRange total_range{address, static_cast<std::uint64_t>(data.size())};
    auto end_res = total_range.end();
    if (!end_res) {
        return std::unexpected(end_res.error());
    }
    const std::uint64_t end = end_res->value();
    const IMemoryBackend& backend = memory_backend(process_);

    // Pass 1: Validate that the entire target range is committed and not a guard page
    struct RegionSlice {
        Address slice_begin;
        std::size_t slice_size;
        MemoryProtection original_protection;
        bool needs_protect_change;
    };

    std::vector<RegionSlice> slices;
    std::vector<std::byte> backup_bytes;

    try {
        for (std::uint64_t cur = address.value(); cur < end;) {
            auto q = backend.query(Address{cur});
            if (!q) {
                return std::unexpected(q.error());
            }
            if (!q->is_committed() || q->is_guard() ||
                has_flag(q->protection, MemoryProtection::NoAccess)) {
                return fail(ErrorCode::AccessDenied,
                            "MemoryWriter::write_with_report",
                            0,
                            "Target range contains uncommitted, guard, or no-access pages");
            }
            auto r_end = checked_add<std::uint64_t>(q->base.value(), q->size);
            if (!r_end || *r_end <= cur) {
                return fail(ErrorCode::AddressOverflow, "MemoryWriter::write_with_report");
            }
            const std::uint64_t slice_end = (std::min)(*r_end, end);
            const auto slice_len = static_cast<std::size_t>(slice_end - cur);
            slices.push_back(RegionSlice{
                .slice_begin = Address{cur},
                .slice_size = slice_len,
                .original_protection = q->protection,
                .needs_protect_change = !q->is_writable(),
            });
            cur = slice_end;
        }

        if (options.rollback_on_failure) {
            backup_bytes.resize(data.size());
            auto got = backend.read(address, backup_bytes);
            if (!got || *got != data.size()) {
                return fail(ErrorCode::AccessDenied,
                            "MemoryWriter::write_with_report",
                            0,
                            "Failed to read original bytes for rollback safety before writing");
            }
        }
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "MemoryWriter::write_with_report");
    }

    // Reserve restoration tickets before touching memory. Once a page is made
    // writable, recording a failed restoration must not itself allocate/fail.
    WriteReport report{};
    if (slices.size() > report.pending_protection_restores.max_size() / 2) {
        return fail(ErrorCode::OutOfMemory, "MemoryWriter::write_with_report");
    }
    try {
        report.pending_protection_restores.reserve(slices.size() * 2);
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "MemoryWriter::write_with_report");
    }

    // Pass 2: Write region by region, elevating and restoring page protection per slice
    std::size_t offset = 0;

    for (const auto& slice : slices) {
        MemoryProtection restore_prot = slice.original_protection;
        if (slice.needs_protect_change) {
            const MemoryProtection elevated =
                has_flag(slice.original_protection, MemoryProtection::Execute)
                    ? MemoryProtection::ExecuteReadWrite
                    : MemoryProtection::ReadWrite;
            auto prot_res = backend.protect(slice.slice_begin, slice.slice_size, elevated);
            if (!prot_res) {
                report.write_error = prot_res.error();
                break;
            }
            restore_prot = *prot_res;
        }

        const auto chunk = data.subspan(offset, slice.slice_size);
        auto written_res = backend.write(slice.slice_begin, chunk);

        if (slice.needs_protect_change) {
            auto restore_res = backend.protect(slice.slice_begin, slice.slice_size, restore_prot);
            if (!restore_res && !report.protection_restore_warning) {
                report.protection_restore_warning = make_error(
                    ErrorCode::ProtectionRestoreFailed,
                    restore_res.error().operation,
                    restore_res.error().native,
                    "Failed to restore original page protection after write");
                report.pending_protection_restores.push_back(PendingProtectionRestore{
                    .range = AddressRange{slice.slice_begin, slice.slice_size},
                    .original_protection = restore_prot,
                });
                diagnostics::notify(process_.observer(),
                                    DiagnosticSeverity::Warning,
                                    "MemoryWriter",
                                    "Failed to restore page protection; retry ownership is retained in WriteReport",
                                    report.protection_restore_warning);
            }
        }

        ++report.regions_touched;
        if (!written_res) {
            report.write_error = written_res.error();
            break;
        }
        report.bytes_written += *written_res;
        offset += *written_res;
        if (*written_res != slice.slice_size) {
            report.write_error = make_error(
                ErrorCode::PartialTransfer, "WriteProcessMemory", 0, "Partial region write");
            break;
        }
    }

    // Step 3: Rollback on mid-write failure if bytes were already modified
    if (report.write_error && options.rollback_on_failure && report.bytes_written > 0) {
        report.rolled_back = true;
        std::size_t rb_offset = 0;
        for (const auto& slice : slices) {
            if (rb_offset >= report.bytes_written) {
                break;
            }
            const std::size_t to_restore =
                (std::min)(slice.slice_size, report.bytes_written - rb_offset);
            MemoryProtection restore_prot = slice.original_protection;
            if (slice.needs_protect_change) {
                const MemoryProtection elevated =
                    has_flag(slice.original_protection, MemoryProtection::Execute)
                        ? MemoryProtection::ExecuteReadWrite
                        : MemoryProtection::ReadWrite;
                auto p = backend.protect(slice.slice_begin, to_restore, elevated);
                if (!p) {
                    report.rollback_error = p.error();
                    break;
                }
                restore_prot = *p;
            }
            auto w = backend.write(
                slice.slice_begin,
                std::span<const std::byte>(backup_bytes.data() + rb_offset, to_restore));
            if (slice.needs_protect_change) {
                auto restore_result = backend.protect(slice.slice_begin, to_restore, restore_prot);
                if (!restore_result) {
                    report.pending_protection_restores.push_back(PendingProtectionRestore{
                        .range = AddressRange{slice.slice_begin, to_restore},
                        .original_protection = restore_prot,
                    });
                    if (!report.protection_restore_warning) {
                        report.protection_restore_warning = make_error(
                            ErrorCode::ProtectionRestoreFailed,
                            restore_result.error().operation,
                            restore_result.error().native,
                            "Failed to restore page protection during rollback");
                    }
                }
            }
            if (!w || *w != to_restore) {
                if (!report.rollback_error) {
                    report.rollback_error =
                        w ? make_error(ErrorCode::PartialTransfer, "RollbackWrite") : w.error();
                }
                break;
            }
            rb_offset += to_restore;
        }
        report.rolled_back = !report.rollback_error.has_value() &&
                            rb_offset == report.bytes_written;
    }

    // Step 4: Flush instruction cache. A failed flush is a safety failure,
    // even when the bytes were written successfully.
    if (options.flush_icache && report.bytes_written > 0) {
        auto flush_status = backend.flush_instruction_cache(
            AddressRange{address, static_cast<std::uint64_t>(report.bytes_written)});
        if (!flush_status) {
            report.icache_flush_error = flush_status.error();
        }
    }

    return report;
}

Status MemoryWriter::write(Address address,
                           std::span<const std::byte> data,
                           WriteOptions options) const {
    auto rep = write_with_report(address, data, options);
    if (!rep) {
        return std::unexpected(rep.error());
    }
    if (rep->write_error) {
        return std::unexpected(*rep->write_error);
    }
    if (rep->rollback_error) {
        return std::unexpected(*rep->rollback_error);
    }
    if (rep->protection_restore_warning) {
        return std::unexpected(*rep->protection_restore_warning);
    }
    if (rep->icache_flush_error) {
        return std::unexpected(*rep->icache_flush_error);
    }
    return ok();
}

Status MemoryWriter::fill(Address address,
                          std::byte value,
                          std::size_t count,
                          WriteOptions options) const {
    if (count == 0) {
        return address.is_null() ? fail(ErrorCode::NullAddress, "MemoryWriter::fill") : ok();
    }
    try {
        std::vector<std::byte> buf(count, value);
        return write(address, buf, options);
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "MemoryWriter::fill");
    }
}

} // namespace tessera
