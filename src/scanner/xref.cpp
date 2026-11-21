#include "tessera/scanner/xref.hpp"
#include "scanner_detail.hpp"
#include "disasm/x86_instruction_decoder.hpp"
#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_backend.hpp"
#include "tessera/module/pe_image.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <utility>
namespace tessera {
using scanner_detail::for_each_readable_chunk;
namespace xref {

Result<XrefBatchScanResult> find_decoded_xrefs_batch(const Process& process, AddressRange instruction_range,
                                                     std::span<const Address> targets,
                                                     const ScanOptions& options) {
    if (instruction_range.empty() || targets.empty() ||
        std::any_of(targets.begin(), targets.end(), [](Address target) { return target.is_null(); })) {
        return fail(ErrorCode::InvalidArgument, "xref::find_decoded_xrefs_batch");
    }
    auto range_end = instruction_range.end();
    if (!range_end) {
        return std::unexpected(range_end.error());
    }
    auto max_exclusive = checked_add<std::uint64_t>(process.info().max_application_address, 1u);
    if (!max_exclusive || range_end->value() > *max_exclusive) {
        return fail(ErrorCode::OutOfRange, "xref::find_decoded_xrefs_batch");
    }

    try {
        XrefBatchScanResult batch{};
        batch.results.resize(targets.size());
        const IMemoryBackend& backend = memory_backend(process);
        std::uint64_t cursor = instruction_range.begin().value();
        std::uint64_t region_end = 0;
        while (cursor < range_end->value()) {
            if (options.stop.stop_requested()) {
                for (auto& result : batch.results) {
                    result.cancelled = true;
                }
                break;
            }

            if (cursor >= region_end) {
                auto region = backend.query(Address{cursor});
                if (!region) {
                    return std::unexpected(region.error());
                }
                if (!matches_region_filter(*region, options.filter)) {
                    return fail(ErrorCode::AccessDenied, "xref::find_decoded_xrefs_batch", 0,
                                "Instruction sweep entered a filtered or inaccessible region");
                }
                auto next_region = checked_add<std::uint64_t>(region->base.value(), region->size);
                if (!next_region || *next_region <= cursor) {
                    return fail(ErrorCode::OutOfRange, "xref::find_decoded_xrefs_batch", 0,
                                "Memory-region query returned an invalid range");
                }
                region_end = *next_region;
                for (auto& result : batch.results) {
                    ++result.stats.regions_scanned;
                }
            }

            const std::uint64_t remaining = range_end->value() - cursor;
            const std::size_t available = static_cast<std::size_t>(
                (std::min)((std::min)(std::uint64_t{15}, remaining), region_end - cursor));
            std::array<std::byte, 15> raw{};
            auto read = backend.read(Address{cursor}, std::span<std::byte>{raw}.first(available));
            if (!read || *read != available) {
                for (auto& result : batch.results) {
                    ++result.stats.read_errors;
                }
                return fail(ErrorCode::PartialTransfer, "xref::find_decoded_xrefs_batch",
                            read ? 0 : read.error().native,
                            "Instruction sweep requires complete bounded reads");
            }

            ::tessera::detail::x86::DecodedInstruction decoded{};
            const auto mode = process.pointer_size() == 8 ? ::tessera::detail::x86::Mode::x64
                                                          : ::tessera::detail::x86::Mode::x86;
            if (!::tessera::detail::x86::decode_instruction(raw.data(), available, mode, decoded) ||
                decoded.length == 0 || decoded.length > remaining) {
                return fail(ErrorCode::UnsupportedInstruction, "xref::find_decoded_xrefs_batch", 0,
                            "Instruction boundary cannot be established at sweep cursor");
            }

            bool matched = false;
            Address resolved_target{};
            XrefKind kind = XrefKind::DirectCall;
            if (decoded.has_relative_operand &&
                (decoded.relative_size == 1u || decoded.relative_size == 4u) &&
                decoded.relative_offset + decoded.relative_size <= decoded.length) {
                std::int64_t displacement = 0;
                if (decoded.relative_size == 1) {
                    displacement =
                        static_cast<std::int8_t>(std::to_integer<std::uint8_t>(raw[decoded.relative_offset]));
                } else if (decoded.relative_size == 4) {
                    std::int32_t rel32 = 0;
                    std::memcpy(&rel32, raw.data() + decoded.relative_offset, sizeof(rel32));
                    displacement = rel32;
                }
                auto next_ip = checked_add<std::uint64_t>(cursor, static_cast<std::uint64_t>(decoded.length));
                if (!next_ip) {
                    return fail(ErrorCode::OutOfRange, "xref::find_decoded_xrefs_batch");
                }
                auto destination = checked_offset<std::uint64_t>(*next_ip, displacement);
                if (destination) {
                    const bool direct_call = decoded.opcode == 0xE8u;
                    const bool direct_jump = decoded.opcode == 0xE9u || decoded.opcode == 0xEBu;
                    const bool short_conditional = decoded.opcode >= 0x70u && decoded.opcode <= 0x7Fu;
                    const bool near_conditional =
                        decoded.opcode == 0x0Fu && decoded.opcode2 >= 0x80u && decoded.opcode2 <= 0x8Fu;
                    if (direct_call || direct_jump || short_conditional || near_conditional) {
                        resolved_target = Address{*destination};
                        matched = true;
                        kind = direct_call   ? XrefKind::DirectCall
                               : direct_jump ? XrefKind::DirectJump
                                             : XrefKind::ConditionalBranch;
                    }
                }
            }

            if (!matched && process.pointer_size() == 4u && decoded.opcode == 0xFFu && decoded.length == 6u &&
                (raw[1] == std::byte{0x15} || raw[1] == std::byte{0x25}) &&
                (decoded.modrm_reg == 2u || decoded.modrm_reg == 4u)) {
                std::uint32_t slot32 = 0;
                std::memcpy(&slot32, raw.data() + 2, sizeof(slot32));
                std::array<std::byte, sizeof(std::uint64_t)> pointer_bytes{};
                auto pointer_read = backend.read(
                    Address{slot32}, std::span<std::byte>{pointer_bytes}.first(sizeof(std::uint32_t)));
                if (pointer_read && *pointer_read == sizeof(std::uint32_t)) {
                    std::uint32_t pointer_value = 0;
                    std::memcpy(&pointer_value, pointer_bytes.data(), sizeof(pointer_value));
                    resolved_target = Address{pointer_value};
                    matched = true;
                    kind = decoded.modrm_reg == 2u ? XrefKind::IndirectCall : XrefKind::IndirectJump;
                }
            }

            if (!matched && decoded.has_rip_relative_operand &&
                decoded.rip_displacement_offset + sizeof(std::int32_t) <= decoded.length) {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, raw.data() + decoded.rip_displacement_offset,
                            sizeof(displacement));
                auto next_ip = checked_add<std::uint64_t>(cursor, static_cast<std::uint64_t>(decoded.length));
                if (!next_ip) {
                    return fail(ErrorCode::OutOfRange, "xref::find_decoded_xrefs_batch");
                }
                auto slot = checked_offset<std::uint64_t>(*next_ip, displacement);
                if (slot) {
                    resolved_target = Address{*slot};
                    const bool indirect_call = decoded.opcode == 0xFFu && decoded.modrm_reg == 2u;
                    const bool indirect_jump = decoded.opcode == 0xFFu && decoded.modrm_reg == 4u;
                    if (indirect_call || indirect_jump) {
                        std::array<std::byte, sizeof(std::uint64_t)> pointer_bytes{};
                        const std::size_t pointer_size = process.pointer_size();
                        auto pointer_read = backend.read(
                            Address{*slot}, std::span<std::byte>{pointer_bytes}.first(pointer_size));
                        if (pointer_read && *pointer_read == pointer_size) {
                            std::uint64_t pointer_value = 0;
                            if (pointer_size == 8u) {
                                std::memcpy(&pointer_value, pointer_bytes.data(), sizeof(pointer_value));
                            } else {
                                std::uint32_t pointer32 = 0;
                                std::memcpy(&pointer32, pointer_bytes.data(), sizeof(pointer32));
                                pointer_value = pointer32;
                            }
                            resolved_target = Address{pointer_value};
                            matched = true;
                            kind = indirect_call ? XrefKind::IndirectCall : XrefKind::IndirectJump;
                        }
                    } else {
                        matched = true;
                        kind = XrefKind::RipRelativeData;
                    }
                }
            }

            if (matched) {
                for (std::size_t target_index = 0; target_index < targets.size(); ++target_index) {
                    if (targets[target_index] != resolved_target) {
                        continue;
                    }
                    auto& result = batch.results[target_index];
                    if (options.max_results > 0 && result.references.size() >= options.max_results) {
                        result.truncated = true;
                        continue;
                    }
                    result.references.push_back(XrefMatch{
                        .instruction = Address{cursor},
                        .target = resolved_target,
                        .kind = kind,
                    });
                    if (options.max_results > 0 && result.references.size() >= options.max_results) {
                        result.truncated = true;
                    }
                }
            }

            cursor += decoded.length;
            for (auto& result : batch.results) {
                result.stats.bytes_scanned += decoded.length;
            }
            if (options.on_progress) {
                std::size_t total_hits = 0;
                for (const auto& result : batch.results) {
                    total_hits += result.references.size();
                }
                options.on_progress(ScanProgress{
                    .bytes_scanned = batch.results.front().stats.bytes_scanned,
                    .total_bytes = instruction_range.size(),
                    .hits_found = total_hits,
                });
            }
            if (options.max_results > 0 &&
                std::all_of(batch.results.begin(), batch.results.end(), [&](const XrefScanResult& result) {
                    return result.references.size() >= options.max_results;
                })) {
                for (auto& result : batch.results) {
                    result.truncated = true;
                }
                break;
            }
        }
        return batch;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "xref::find_decoded_xrefs_batch");
    }
}

Result<XrefScanResult> find_decoded_xrefs(const Process& process, AddressRange instruction_range,
                                          Address target, const ScanOptions& options) {
    const std::array<Address, 1> targets{target};
    auto batch = find_decoded_xrefs_batch(process, instruction_range, targets, options);
    if (!batch) {
        return std::unexpected(batch.error());
    }
    return std::move(batch->results.front());
}

namespace {

template <class Predicate>
[[nodiscard]] Result<std::vector<Address>>
filter_decoded_references(const Process& process, std::vector<Address> candidates, Predicate&& predicate) {
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
            const auto mode = process.pointer_size() == 8 ? ::tessera::detail::x86::Mode::x64
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

Result<std::vector<Address>> find_pointer_refs(const Process& process, AddressRange range, Address target,
                                               const ScanOptions& options) {
    if (target.is_null()) {
        return fail(ErrorCode::NullAddress, "xref::find_pointer_refs");
    }
    const std::uint8_t ptr_size = process.pointer_size();
    if (ptr_size == 4 && target.value() > 0xFFFFFFFFULL) {
        return fail(ErrorCode::OutOfRange, "xref::find_pointer_refs", 0,
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

Result<std::vector<std::vector<Address>>> find_pointer_refs_batch(const Process& process, AddressRange range,
                                                                  std::span<const Address> targets,
                                                                  const ScanOptions& options) {
    if (targets.empty()) {
        return fail(ErrorCode::InvalidArgument, "xref::find_pointer_refs_batch", 0, "Target batch is empty");
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
                return fail(ErrorCode::OutOfRange, "xref::find_pointer_refs_batch", 0,
                            "Target address exceeds x86 pointer range");
            }
            auto pattern =
                pointer_size == 8
                    ? Pattern::from_value<std::uint64_t>(target.value())
                    : Pattern::from_value<std::uint32_t>(static_cast<std::uint32_t>(target.value()));
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

Result<std::vector<Address>> find_rel32_refs(const Process& process, AddressRange range, Address target,
                                             const Pattern& prefix, std::size_t trailing_bytes,
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
            process, range, full_pat->size() - 1, options, cancelled,
            [&](std::span<const std::byte> data, std::size_t start_limit, Address chunk_base, std::uint64_t,
                std::uint64_t) -> bool {
                bool more = true;
                full_pat->search(data, start_limit, [&](std::size_t off) -> bool {
                    std::int32_t disp = 0;
                    std::memcpy(&disp, data.data() + off + pre_len, sizeof(disp));
                    const std::uint64_t ins_addr = chunk_base.value() + off;
                    auto next_ip =
                        checked_add<std::uint64_t>(ins_addr, static_cast<std::uint64_t>(*instruction_span));
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

Result<std::vector<Address>> find_calls(const Process& process, AddressRange range, Address target,
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
        process, std::move(*candidates), [](const ::tessera::detail::x86::DecodedInstruction& decoded) {
            return decoded.opcode == 0xE8u && decoded.has_relative_operand && decoded.relative_size == 4;
        });
}

Result<std::vector<Address>> find_jumps(const Process& process, AddressRange range, Address target,
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
        process, std::move(*candidates), [](const ::tessera::detail::x86::DecodedInstruction& decoded) {
            return decoded.opcode == 0xE9u && decoded.has_relative_operand && decoded.relative_size == 4;
        });
}

Result<std::vector<Address>> find_conditional_branches(const Process& process, AddressRange range,
                                                       Address target, const ScanOptions& options) {
    auto prefix = Pattern::parse("0F 8?");
    if (!prefix) {
        return std::unexpected(prefix.error());
    }
    auto candidates = find_rel32_refs(process, range, target, *prefix, 0, options);
    if (!candidates) {
        return std::unexpected(candidates.error());
    }
    return filter_decoded_references(
        process, std::move(*candidates), [](const ::tessera::detail::x86::DecodedInstruction& decoded) {
            return decoded.opcode == 0x0Fu && decoded.opcode2 >= 0x80u && decoded.opcode2 <= 0x8Fu &&
                   decoded.has_relative_operand && decoded.relative_size == 4;
        });
}

Result<std::vector<Address>> find_indirect_refs(const Process& process, AddressRange range, Address target,
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
                const auto mode = process.pointer_size() == 8 ? ::tessera::detail::x86::Mode::x64
                                                              : ::tessera::detail::x86::Mode::x86;
                if (!::tessera::detail::x86::decode_instruction(raw.data(), *read, mode, decoded) ||
                    decoded.opcode != 0xFFu || (decoded.modrm_reg != 2u && decoded.modrm_reg != 4u) ||
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
                    auto next_ip = checked_add<std::uint64_t>(instruction.value(),
                                                              static_cast<std::uint64_t>(decoded.length));
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

Result<std::vector<Address>> find_relocated_pointer_refs(const Process& process, Address module_base,
                                                         const PeImage& image, Address target) {
    if (module_base.is_null() || target.is_null()) {
        return fail(ErrorCode::NullAddress, "xref::find_relocated_pointer_refs");
    }
    const std::size_t pointer_size = image.kind() == PeKind::Pe32Plus ? 8u : 4u;
    if (process.pointer_size() != pointer_size) {
        return fail(ErrorCode::UnsupportedArchitecture, "xref::find_relocated_pointer_refs", 0,
                    "Process and PE image architectures do not match");
    }
    try {
        std::vector<Address> references;
        for (const auto& relocation : image.relocations()) {
            const bool pointer_relocation = (pointer_size == 4u && relocation.type == 3u) ||
                                            (pointer_size == 8u && relocation.type == 10u);
            if (!pointer_relocation) {
                continue;
            }
            auto location = module_base.add_rva(relocation.location);
            if (!location) {
                return std::unexpected(location.error());
            }
            std::array<std::byte, sizeof(std::uint64_t)> raw{};
            auto read =
                memory_backend(process).read(*location, std::span<std::byte>{raw}.first(pointer_size));
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
