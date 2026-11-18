#include "tessera/rtti/rtti.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <new>
#include <unordered_map>
#include <unordered_set>

#include "tessera/memory/memory_reader.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/scanner/xref.hpp"

namespace tessera::rtti {

namespace {

[[nodiscard]] bool icontains_str(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    auto to_lower = [](char c) noexcept -> unsigned char {
        const auto uc = static_cast<unsigned char>(c);
        return (uc >= 'A' && uc <= 'Z') ? static_cast<unsigned char>(uc + 32u) : uc;
    };
    for (std::size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (to_lower(haystack[i + j]) != to_lower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string decode_basic_template_arg(std::string_view code) {
    if (code == "H") return "int";
    if (code == "I") return "unsigned int";
    if (code == "M") return "float";
    if (code == "N") return "double";
    if (code == "_N") return "bool";
    if (code == "D") return "char";
    if (code == "E") return "unsigned char";
    if (code == "F") return "short";
    if (code == "G") return "unsigned short";
    if (code == "_J") return "int64_t";
    if (code == "_K") return "uint64_t";
    if (code == "X") return "void";
    return std::string(code);
}

[[nodiscard]] std::string demangle_template_part(std::string_view part) {
    // e.g. "?$Vector@M" -> "Vector<float>"
    if (!part.starts_with("?$")) {
        return std::string(part);
    }
    part.remove_prefix(2);
    const auto at_pos = part.find('@');
    if (at_pos == std::string_view::npos) {
        return std::string(part);
    }
    const std::string_view tpl_name = part.substr(0, at_pos);
    std::string_view args_str = part.substr(at_pos + 1);
    std::vector<std::string> args;
    while (!args_str.empty()) {
        if (args_str.starts_with("@")) {
            break;
        }
        const auto next_at = args_str.find('@');
        const std::string_view token =
            (next_at == std::string_view::npos) ? args_str : args_str.substr(0, next_at);
        if (!token.empty()) {
            args.push_back(decode_basic_template_arg(token));
        }
        if (next_at == std::string_view::npos) {
            break;
        }
        args_str.remove_prefix(next_at + 1);
    }
    std::string out(tpl_name);
    out.push_back('<');
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i > 0) {
            out += ", ";
        }
        out += args[i];
    }
    out.push_back('>');
    return out;
}

[[nodiscard]] Result<std::string> read_type_descriptor_name(const MemoryReader& reader,
                                                            Address td_addr,
                                                            std::uint8_t ptr_size) {
    const std::int64_t name_off = (ptr_size == 8) ? 16 : 8;
    auto name_addr = td_addr.offset(name_off);
    if (!name_addr) {
        return std::unexpected(name_addr.error());
    }
    return reader.read_cstring(*name_addr, 512);
}

} // namespace

std::string demangle_msvc_symbol(std::string_view mangled) {
    if (mangled.empty()) {
        return {};
    }
    std::string_view s = mangled;
    if (s.starts_with(".?AV") || s.starts_with(".?AU") || s.starts_with(".?AT")) {
        s.remove_prefix(4);
    } else if (s.starts_with(".?AW4")) {
        s.remove_prefix(5);
    } else if (s.starts_with(".?")) {
        s.remove_prefix(2);
    } else {
        return std::string(mangled);
    }

    if (s.ends_with("@@")) {
        s.remove_suffix(2);
    } else if (s.ends_with("@")) {
        s.remove_suffix(1);
    }

    std::vector<std::string> parts;
    std::size_t pos = 0;
    while (pos < s.size()) {
        if (s.substr(pos).starts_with("?$")) {
            // Find end of template instantiation "@@" if nested, or parse "?$Tpl@Arg" before "@Scope"
            const auto dbl_at = s.find("@@", pos);
            if (dbl_at != std::string_view::npos) {
                parts.push_back(demangle_template_part(s.substr(pos, dbl_at - pos)));
                pos = dbl_at + 2;
                continue;
            }
            // Single-arg template followed by outer scope (after trailing "@@" was stripped):
            // e.g. "?$Vector@M@Math" -> template part "?$Vector@M", remaining "Math"
            const auto first_at = s.find('@', pos + 2);
            if (first_at != std::string_view::npos) {
                const auto second_at = s.find('@', first_at + 1);
                if (second_at != std::string_view::npos) {
                    parts.push_back(demangle_template_part(s.substr(pos, second_at - pos)));
                    pos = second_at + 1;
                    continue;
                }
            }
            parts.push_back(demangle_template_part(s.substr(pos)));
            break;
        }
        const auto next_at = s.find('@', pos);
        if (next_at == std::string_view::npos) {
            const auto tail = s.substr(pos);
            if (!tail.empty()) {
                parts.push_back(demangle_template_part(tail));
            }
            break;
        }
        const auto token = s.substr(pos, next_at - pos);
        if (!token.empty()) {
            if (token.starts_with("?A0x")) {
                parts.emplace_back("`anonymous-namespace'");
            } else {
                parts.push_back(demangle_template_part(token));
            }
        }
        pos = next_at + 1;
    }

    if (parts.empty()) {
        return std::string(mangled);
    }

    std::string result;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!result.empty()) {
            result += "::";
        }
        result += *it;
    }
    return result;
}

Result<RttiClassDescriptor> RttiCatalog::inspect_vftable(const Process& process,
                                                         AddressRange module_range,
                                                         Address vftable_address) {
    if (vftable_address.is_null() || !module_range.contains(vftable_address)) {
        return fail(ErrorCode::InvalidArgument, "RttiCatalog::inspect_vftable");
    }

    const std::uint8_t ptr_size = process.pointer_size();
    // The PE32+ RTTI structures store RVAs relative to the image base.
    const Address mod_base = module_range.begin();
    MemoryReader reader{process};

    auto meta_slot = vftable_address.offset(-static_cast<std::int64_t>(ptr_size));
    if (!meta_slot) {
        return std::unexpected(meta_slot.error());
    }
    auto col_addr_res = reader.read_pointer(*meta_slot);
    if (!col_addr_res || !module_range.contains(*col_addr_res)) {
        return fail(ErrorCode::NotFound, "RttiCatalog::inspect_vftable", 0, "Invalid COL pointer");
    }
    const Address col_addr = *col_addr_res;

    std::array<std::uint32_t, 6> col_words{};
    const std::size_t col_bytes = (ptr_size == 8) ? 24u : 20u;
    if (!reader.read_exact(
            col_addr, std::as_writable_bytes(std::span<std::uint32_t>(col_words.data(), col_bytes / 4u)))) {
        return fail(ErrorCode::PartialTransfer, "RttiCatalog::inspect_vftable");
    }

    const std::uint32_t sig = col_words[0];
    const std::uint32_t offset = col_words[1];
    const std::uint32_t cd_offset = col_words[2];
    const std::uint32_t td_ref = col_words[3];
    const std::uint32_t chd_ref = col_words[4];

    Address td_addr{};
    Address chd_addr{};
    if (ptr_size == 8) {
        if (sig != 1u) {
            return fail(ErrorCode::ValidationFailed, "RttiCatalog::inspect_vftable", 0, "COL signature != 1");
        }
        const std::uint32_t self_rva = col_words[5];
        auto col_rva = module_range.to_rva(col_addr);
        if (!col_rva || col_rva->value() != self_rva) {
            return fail(ErrorCode::ValidationFailed, "RttiCatalog::inspect_vftable", 0, "COL pSelf mismatch");
        }
        auto td_a = mod_base.add_rva(Rva{td_ref});
        auto chd_a = mod_base.add_rva(Rva{chd_ref});
        if (!td_a || !chd_a || !module_range.contains(*td_a) || !module_range.contains(*chd_a)) {
            return fail(ErrorCode::ValidationFailed, "RttiCatalog::inspect_vftable");
        }
        td_addr = *td_a;
        chd_addr = *chd_a;
    } else {
        if (sig != 0u) {
            return fail(ErrorCode::ValidationFailed, "RttiCatalog::inspect_vftable", 0, "COL signature != 0");
        }
        td_addr = Address{td_ref};
        chd_addr = Address{chd_ref};
        if (!module_range.contains(td_addr) || !module_range.contains(chd_addr)) {
            return fail(ErrorCode::ValidationFailed, "RttiCatalog::inspect_vftable");
        }
    }

    auto mangled_res = read_type_descriptor_name(reader, td_addr, ptr_size);
    if (!mangled_res || !mangled_res->starts_with(".?A")) {
        return fail(ErrorCode::ValidationFailed, "RttiCatalog::inspect_vftable", 0, "Invalid TD name");
    }

    RttiClassDescriptor desc{};
    desc.mangled_name = std::move(*mangled_res);
    desc.demangled_name = demangle_msvc_symbol(desc.mangled_name);
    desc.type_id = reflection::TypeId::from_name(desc.demangled_name);
    desc.vftable_address = vftable_address;
    if (auto rva = module_range.to_rva(vftable_address)) {
        desc.vftable_rva = *rva;
    }
    desc.col_address = col_addr;
    desc.type_descriptor_address = td_addr;
    desc.chd_address = chd_addr;
    desc.offset = offset;
    desc.cd_offset = cd_offset;

    // Parse ClassHierarchyDescriptor (16 bytes)
    std::array<std::uint32_t, 4> chd_words{};
    if (reader.read_exact(chd_addr, std::as_writable_bytes(std::span(chd_words)))) {
        desc.chd_attributes = chd_words[1];
        const std::uint32_t num_bases = (std::min)(chd_words[2], 64u);
        const std::uint32_t bca_ref = chd_words[3];
        Address bca_addr{};
        if (ptr_size == 8) {
            if (auto a = mod_base.add_rva(Rva{bca_ref})) {
                bca_addr = *a;
            }
        } else {
            bca_addr = Address{bca_ref};
        }

        if (module_range.contains(bca_addr)) {
            for (std::uint32_t bi = 0; bi < num_bases; ++bi) {
                auto entry_loc = bca_addr.offset(static_cast<std::int64_t>(bi * 4u));
                if (!entry_loc) {
                    break;
                }
                auto bcd_ref = reader.read<std::uint32_t>(*entry_loc);
                if (!bcd_ref) {
                    break;
                }
                Address bcd_addr{};
                if (ptr_size == 8) {
                    if (auto a = mod_base.add_rva(Rva{*bcd_ref})) {
                        bcd_addr = *a;
                    }
                } else {
                    bcd_addr = Address{*bcd_ref};
                }
                if (!module_range.contains(bcd_addr)) {
                    continue;
                }
                std::array<std::int32_t, 7> bcd_words{};
                if (!reader.read_exact(bcd_addr, std::as_writable_bytes(std::span(bcd_words)))) {
                    continue;
                }
                const auto base_td_ref = static_cast<std::uint32_t>(bcd_words[0]);
                Address base_td_addr{};
                if (ptr_size == 8) {
                    if (auto a = mod_base.add_rva(Rva{base_td_ref})) {
                        base_td_addr = *a;
                    }
                } else {
                    base_td_addr = Address{base_td_ref};
                }
                if (!module_range.contains(base_td_addr)) {
                    continue;
                }
                auto base_mangled = read_type_descriptor_name(reader, base_td_addr, ptr_size);
                if (!base_mangled || !base_mangled->starts_with(".?A")) {
                    continue;
                }
                // Skip self entry at index 0 if it points to the same TypeDescriptor and mdisp == 0
                if (bi == 0 && base_td_addr == td_addr && bcd_words[2] == 0 && bcd_words[3] == -1) {
                    continue;
                }
                RttiBaseEntry base_entry{};
                base_entry.mangled_name = std::move(*base_mangled);
                base_entry.demangled_name = demangle_msvc_symbol(base_entry.mangled_name);
                base_entry.type_id = reflection::TypeId::from_name(base_entry.demangled_name);
                base_entry.num_contained_bases = static_cast<std::uint32_t>(bcd_words[1]);
                base_entry.pmd = MsvcPmd{
                    .mdisp = bcd_words[2],
                    .pdisp = bcd_words[3],
                    .vdisp = bcd_words[4],
                };
                base_entry.attributes = static_cast<std::uint32_t>(bcd_words[5]);
                base_entry.type_descriptor_address = base_td_addr;
                desc.base_classes.push_back(std::move(base_entry));
            }
        }
    }

    // Collect virtual method addresses from vftable
    for (std::size_t slot = 0; slot < 128; ++slot) {
        auto slot_addr = vftable_address.offset(static_cast<std::int64_t>(slot * ptr_size));
        if (!slot_addr) {
            break;
        }
        auto fn_ptr = reader.read_pointer(*slot_addr);
        if (!fn_ptr || fn_ptr->is_null() || !module_range.contains(*fn_ptr)) {
            break;
        }
        auto is_exec = reader.is_executable(AddressRange{*fn_ptr, 1});
        if (!is_exec || !*is_exec) {
            break;
        }
        desc.virtual_methods.push_back(*fn_ptr);
    }

    return desc;
}

Result<RttiCatalog> RttiCatalog::discover_all(const Process& process,
                                              AddressRange module_range,
                                              const PeImage*) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "RttiCatalog::discover_all");
    }

    try {
        RttiCatalog catalog{};
        catalog.module_base_ = module_range.begin();
        const std::uint8_t ptr_size = process.pointer_size();

        // 1. Find all ".?AV" and ".?AU" strings inside module_range
        static constexpr std::array<std::byte, 3> kRttiPrefix{
            std::byte{'.'}, std::byte{'?'}, std::byte{'A'}};
        auto pat = Pattern::from_bytes(kRttiPrefix);
        if (!pat) {
            return std::unexpected(pat.error());
        }

        Scanner scanner{process};
        auto scan_res = scanner.scan(module_range, *pat);
        if (!scan_res) {
            return std::unexpected(scan_res.error());
        }

        const std::int64_t name_off = (ptr_size == 8) ? 16 : 8;
        std::unordered_set<std::uint32_t> valid_td_refs;
        for (const Address hit : scan_res->hits) {
            auto td_addr = hit.offset(-name_off);
            if (!td_addr || !module_range.contains(*td_addr)) {
                continue;
            }
            if (ptr_size == 8) {
                if (auto rva = module_range.to_rva(*td_addr)) {
                    valid_td_refs.insert(rva->value());
                }
            } else {
                valid_td_refs.insert(static_cast<std::uint32_t>(td_addr->value()));
            }
        }

        if (valid_td_refs.empty()) {
            return catalog;
        }

        // 2. Scan readable regions in module_range for COL structures referencing those TypeDescriptors
        MemoryReader reader{process};
        std::unordered_set<std::uint64_t> valid_cols;

        const std::uint64_t mod_begin = module_range.begin().value();
        const std::uint64_t mod_end = mod_begin + module_range.size();
        constexpr std::size_t kChunk = 64 * 1024;

        auto for_each_region_chunk = [&](auto&& fn) {
            std::uint64_t cur = mod_begin;
            while (cur < mod_end) {
                auto q = reader.query(Address{cur});
                if (!q || q->size == 0) {
                    break;
                }
                const std::uint64_t reg_end = q->base.value() + q->size;
                if (reg_end <= cur) {
                    break;
                }
                const std::uint64_t clip_begin = (std::max)(cur, q->base.value());
                const std::uint64_t clip_end = (std::min)(reg_end, mod_end);
                if (clip_begin < clip_end && q->state == MemoryState::Committed &&
                    !has_flag(q->protection, MemoryProtection::NoAccess) &&
                    !has_flag(q->protection, MemoryProtection::Guard)) {
                    for (std::uint64_t pos = clip_begin; pos < clip_end; pos += kChunk) {
                        const std::size_t read_len = static_cast<std::size_t>(
                            (std::min)(static_cast<std::uint64_t>(kChunk + 24), clip_end - pos));
                        if (auto got = reader.read_bytes(Address{pos}, read_len)) {
                            fn(pos, *got);
                        }
                    }
                }
                cur = reg_end;
            }
        };

        for_each_region_chunk([&](std::uint64_t chunk_va, const std::vector<std::byte>& bytes) {
            if (bytes.size() < (ptr_size == 8 ? 24u : 20u)) {
                return;
            }
            const std::size_t col_sz = (ptr_size == 8) ? 24u : 20u;
            const std::size_t limit = bytes.size() - col_sz;
            for (std::size_t i = 0; i <= limit; i += 4) {
                std::uint32_t w0 = 0, w3 = 0, w4 = 0, w5 = 0;
                std::memcpy(&w0, bytes.data() + i + 0, 4);
                std::memcpy(&w3, bytes.data() + i + 12, 4);
                std::memcpy(&w4, bytes.data() + i + 16, 4);

                if (ptr_size == 8) {
                    std::memcpy(&w5, bytes.data() + i + 20, 4);
                    const auto cur_rva = static_cast<std::uint32_t>((chunk_va + i) - mod_begin);
                    if (w0 == 1u && w5 == cur_rva && valid_td_refs.contains(w3) &&
                        w4 < module_range.size()) {
                        valid_cols.insert(chunk_va + i);
                    }
                } else {
                    if (w0 == 0u && valid_td_refs.contains(w3) &&
                        module_range.contains(Address{w4})) {
                        valid_cols.insert(chunk_va + i);
                    }
                }
            }
        });

        if (valid_cols.empty()) {
            return catalog;
        }

        // 3. Find vftables: any pointer-aligned slot in module_range containing a valid COL address
        //    where the immediately following slot is a valid vftable.
        std::unordered_set<std::uint64_t> seen_vftables;
        for_each_region_chunk([&](std::uint64_t chunk_va, const std::vector<std::byte>& bytes) {
            if (bytes.size() < ptr_size * 2u) {
                return;
            }
            for (std::size_t i = 0; i + ptr_size <= bytes.size(); i += ptr_size) {
                std::uint64_t ptr_val = 0;
                if (ptr_size == 8) {
                    std::memcpy(&ptr_val, bytes.data() + i, 8);
                } else {
                    std::uint32_t p32 = 0;
                    std::memcpy(&p32, bytes.data() + i, 4);
                    ptr_val = p32;
                }
                if (valid_cols.contains(ptr_val)) {
                    const Address vftable_cand{chunk_va + i + ptr_size};
                    if (!seen_vftables.insert(vftable_cand.value()).second) {
                        continue;
                    }
                    if (auto desc = inspect_vftable(process, module_range, vftable_cand)) {
                        if (!desc->virtual_methods.empty()) {
                            catalog.classes_.push_back(std::move(*desc));
                        }
                    }
                }
            }
        });

        return catalog;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "RttiCatalog::discover_all");
    }
}

Result<RttiClassDescriptor> RttiCatalog::find_class(std::string_view name_or_mangled) const {
    for (const auto& c : classes_) {
        if (c.offset == 0 &&
            (c.demangled_name == name_or_mangled || c.mangled_name == name_or_mangled)) {
            return c;
        }
    }
    for (const auto& c : classes_) {
        if (c.demangled_name == name_or_mangled || c.mangled_name == name_or_mangled) {
            return c;
        }
    }
    return fail(ErrorCode::NotFound, "RttiCatalog::find_class");
}

std::vector<RttiClassDescriptor> RttiCatalog::find_all_vftables(
    std::string_view name_or_mangled) const {
    std::vector<RttiClassDescriptor> out;
    for (const auto& c : classes_) {
        if (c.demangled_name == name_or_mangled || c.mangled_name == name_or_mangled) {
            out.push_back(c);
        }
    }
    return out;
}

std::vector<RttiClassDescriptor> RttiCatalog::search_classes(std::string_view query) const {
    std::vector<RttiClassDescriptor> out;
    for (const auto& c : classes_) {
        if (icontains_str(c.demangled_name, query) || icontains_str(c.mangled_name, query)) {
            out.push_back(c);
        }
    }
    return out;
}

std::vector<RttiClassDescriptor> RttiCatalog::root_classes() const {
    std::vector<RttiClassDescriptor> out;
    for (const auto& c : classes_) {
        if (c.offset == 0 && c.base_classes.empty()) {
            out.push_back(c);
        }
    }
    return out;
}

std::vector<RttiClassDescriptor> RttiCatalog::derived_from(
    std::string_view base_name_or_mangled) const {
    std::vector<RttiClassDescriptor> out;
    for (const auto& c : classes_) {
        if (c.offset != 0) {
            continue;
        }
        for (const auto& b : c.base_classes) {
            if (b.demangled_name == base_name_or_mangled || b.mangled_name == base_name_or_mangled) {
                out.push_back(c);
                break;
            }
        }
    }
    return out;
}

Result<RttiClassDescriptor> RttiCatalog::identify_instance(const Process& process,
                                                           Address instance_addr) const {
    if (instance_addr.is_null()) {
        return fail(ErrorCode::NullAddress, "RttiCatalog::identify_instance");
    }
    MemoryReader reader{process};
    auto vptr = reader.read_pointer(instance_addr);
    if (!vptr || vptr->is_null()) {
        return fail(ErrorCode::NotFound, "RttiCatalog::identify_instance", 0, "Failed to read vptr");
    }
    for (const auto& c : classes_) {
        if (c.vftable_address == *vptr) {
            return c;
        }
    }
    return fail(ErrorCode::NotFound, "RttiCatalog::identify_instance", 0, "vptr not in RttiCatalog");
}

Result<Address> RttiCatalog::cast_to(const Process& process,
                                     Address instance_addr,
                                     std::string_view target_class_name) const {
    auto id_res = identify_instance(process, instance_addr);
    if (!id_res) {
        return std::unexpected(id_res.error());
    }

    // Rewind sub-object pointer to complete object start using COL.offset
    auto complete_obj = instance_addr.offset(-static_cast<std::int64_t>(id_res->offset));
    if (!complete_obj) {
        return std::unexpected(complete_obj.error());
    }

    if (id_res->demangled_name == target_class_name || id_res->mangled_name == target_class_name) {
        return *complete_obj;
    }

    for (const auto& b : id_res->base_classes) {
        if (b.demangled_name == target_class_name || b.mangled_name == target_class_name) {
            if (b.pmd.pdisp < 0) {
                return complete_obj->offset(b.pmd.mdisp);
            }
            // Virtual base class adjustment via vbtable
            MemoryReader reader{process};
            auto vbptr_addr = complete_obj->offset(b.pmd.pdisp);
            if (!vbptr_addr) {
                return std::unexpected(vbptr_addr.error());
            }
            auto vbtable_ptr = reader.read_pointer(*vbptr_addr);
            if (!vbtable_ptr) {
                return std::unexpected(vbtable_ptr.error());
            }
            auto vdisp_entry = vbtable_ptr->offset(b.pmd.vdisp);
            if (!vdisp_entry) {
                return std::unexpected(vdisp_entry.error());
            }
            auto vbase_off = reader.read<std::int32_t>(*vdisp_entry);
            if (!vbase_off) {
                return std::unexpected(vbase_off.error());
            }
            return vbptr_addr->offset(static_cast<std::int64_t>(*vbase_off) + b.pmd.mdisp);
        }
    }

    return fail(ErrorCode::NotFound, "RttiCatalog::cast_to", 0, "Target base class not in hierarchy");
}

Status RttiCatalog::export_to_registry(reflection::TypeRegistry& registry) const {
    for (const auto& c : classes_) {
        if (c.offset != 0) {
            continue;
        }
        reflection::DynamicTypeBuilder builder(c.demangled_name, reflection::TypeKind::Class);
        builder.mangled_name(c.mangled_name)
            .polymorphic(true, c.vftable_rva, c.vftable_address);

        for (const auto& b : c.base_classes) {
            builder.base(reflection::BaseClassInfo{
                .base_type = b.type_id,
                .base_name = b.demangled_name,
                .offset = b.pmd.mdisp,
                .is_virtual = b.is_virtual_base(),
                .mdisp = b.pmd.mdisp,
                .pdisp = b.pmd.pdisp,
                .vdisp = b.pmd.vdisp,
            });
        }

        for (std::size_t idx = 0; idx < c.virtual_methods.size(); ++idx) {
            Rva fn_rva{};
            if (!module_base_.is_null() && c.virtual_methods[idx].value() >= module_base_.value()) {
                fn_rva = Rva{static_cast<std::uint32_t>(c.virtual_methods[idx].value() -
                                                        module_base_.value())};
            }
            builder.method(reflection::MethodInfo{
                .name = std::format("vfunc_{}", idx),
                .kind = reflection::MethodKind::Virtual,
                .vtable_index = idx,
                .rva = fn_rva,
                .address = c.virtual_methods[idx],
            });
        }

        auto st = registry.upsert_type(builder.build());
        if (!st) {
            return st;
        }
    }
    return ok();
}

} // namespace tessera::rtti
