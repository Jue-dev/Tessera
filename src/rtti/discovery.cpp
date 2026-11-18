#include "tessera/rtti/discovery.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <format>
#include <map>
#include <new>
#include <unordered_map>
#include <unordered_set>

#include "tessera/memory/memory_reader.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/scanner/scanner.hpp"

namespace tessera::rtti {

namespace {

[[nodiscard]] bool is_printable_ascii(char c) noexcept {
    const auto uc = static_cast<unsigned char>(c);
    return (uc >= 0x20u && uc <= 0x7Eu) || uc == '\t';
}

[[nodiscard]] bool is_valid_mangled_char(char c) noexcept {
    const auto uc = static_cast<unsigned char>(c);
    return (uc >= 'A' && uc <= 'Z') || (uc >= 'a' && uc <= 'z') || (uc >= '0' && uc <= '9') ||
           c == '@' || c == '?' || c == '$' || c == '_' || c == '.';
}

[[nodiscard]] bool looks_like_source_path(std::string_view s) noexcept {
    if (s.size() < 5) {
        return false;
    }
    return s.ends_with(".cpp") || s.ends_with(".cxx") || s.ends_with(".cc") ||
           s.ends_with(".hpp") || s.ends_with(".h") || s.find(":\\") != std::string_view::npos ||
           s.find("/src/") != std::string_view::npos || s.find("\\src\\") != std::string_view::npos;
}

template <class Fn>
void for_each_readable_chunk(const MemoryReader& reader,
                             AddressRange range,
                             std::size_t overlap,
                             Fn&& fn) {
    const std::uint64_t mod_begin = range.begin().value();
    const std::uint64_t mod_end = mod_begin + range.size();
    constexpr std::size_t kChunk = 64 * 1024;

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
            const bool is_exec = has_flag(q->protection, MemoryProtection::Execute);
            for (std::uint64_t pos = clip_begin; pos < clip_end; pos += kChunk) {
                const std::size_t read_len = static_cast<std::size_t>(
                    (std::min)(static_cast<std::uint64_t>(kChunk + overlap), clip_end - pos));
                if (auto got = reader.read_bytes(Address{pos}, read_len)) {
                    fn(Address{pos}, *got, is_exec);
                }
            }
        }
        cur = reg_end;
    }
}

} // namespace

reflection::TypeInfo ReconstructedStruct::to_type_info() const {
    reflection::DynamicTypeBuilder builder(
        name_hint.empty() ? "InferredStruct" : name_hint,
        reflection::TypeKind::Struct,
        estimated_size);

    for (const auto& f : fields) {
        std::string_view type_name = "uint32";
        reflection::FieldFlags flags = reflection::FieldFlags::Inferred;
        switch (f.kind) {
            case InferredFieldKind::UInt8:
                type_name = "uint8";
                break;
            case InferredFieldKind::Int32:
                type_name = "int32";
                break;
            case InferredFieldKind::Float32:
                type_name = "float";
                break;
            case InferredFieldKind::UInt64OrPointer:
                type_name = "uint64";
                flags |= reflection::FieldFlags::Pointer;
                break;
            case InferredFieldKind::VTablePointer:
                type_name = "vptr";
                flags |= reflection::FieldFlags::Pointer;
                builder.polymorphic(true);
                break;
            case InferredFieldKind::Unknown:
                break;
        }
        builder.field(reflection::FieldInfo{
            .name = std::format("field_{:X}", f.offset),
            .type_id = reflection::TypeId::from_name(type_name),
            .offset = f.offset,
            .size = f.size,
            .flags = flags,
        });
    }
    return builder.build();
}

Result<std::vector<DiscoveredTypeDescriptor>> BinaryExplorer::scan_all_type_descriptors(
    const Process& process,
    AddressRange module_range,
    const RttiCatalog* known_vtable_catalog) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "BinaryExplorer::scan_all_type_descriptors");
    }

    try {
        static constexpr std::array<std::byte, 3> kPrefix{
            std::byte{'.'}, std::byte{'?'}, std::byte{'A'}};
        auto pat = Pattern::from_bytes(kPrefix);
        if (!pat) {
            return std::unexpected(pat.error());
        }

        Scanner scanner{process};
        auto scan_res = scanner.scan(module_range, *pat);
        if (!scan_res) {
            return std::unexpected(scan_res.error());
        }

        std::unordered_set<std::string> vtable_mangled;
        if (known_vtable_catalog != nullptr) {
            for (const auto& c : known_vtable_catalog->classes()) {
                vtable_mangled.insert(c.mangled_name);
            }
        }

        const std::uint8_t ptr_size = process.pointer_size();
        const std::int64_t header_size = (ptr_size == 8) ? 16 : 8;
        MemoryReader reader{process};
        std::vector<DiscoveredTypeDescriptor> results;
        std::unordered_set<std::string> seen;

        for (const Address hit : scan_res->hits) {
            auto str_res = reader.read_cstring(hit, 256);
            if (!str_res || str_res->size() < 6 || !str_res->ends_with("@")) {
                continue;
            }
            const std::string& mangled = *str_res;
            bool all_valid = true;
            for (const char ch : mangled) {
                if (!is_valid_mangled_char(ch)) {
                    all_valid = false;
                    break;
                }
            }
            if (!all_valid) {
                continue;
            }

            DiscoveredTypeKind kind = DiscoveredTypeKind::Class;
            if (mangled.starts_with(".?AV")) {
                kind = DiscoveredTypeKind::Class;
            } else if (mangled.starts_with(".?AU")) {
                kind = DiscoveredTypeKind::Struct;
            } else if (mangled.starts_with(".?AW4")) {
                kind = DiscoveredTypeKind::Enum;
            } else if (mangled.starts_with(".?AT")) {
                kind = DiscoveredTypeKind::Union;
            } else {
                continue;
            }

            if (!seen.insert(mangled).second) {
                continue;
            }

            DiscoveredTypeDescriptor desc{};
            desc.mangled_name = mangled;
            desc.demangled_name = demangle_msvc_symbol(mangled);
            desc.kind = kind;
            desc.type_id = reflection::TypeId::from_name(desc.demangled_name);
            if (auto td_addr = hit.offset(-header_size); td_addr && module_range.contains(*td_addr)) {
                desc.descriptor_address = *td_addr;
                if (auto rva = module_range.to_rva(*td_addr)) {
                    desc.descriptor_rva = *rva;
                }
            } else {
                desc.descriptor_address = hit;
            }
            desc.has_vtable = vtable_mangled.contains(mangled);
            results.push_back(std::move(desc));
        }

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "BinaryExplorer::scan_all_type_descriptors");
    }
}

Result<std::vector<DiscoveredString>> BinaryExplorer::scan_strings(
    const Process& process,
    AddressRange module_range,
    std::size_t min_length,
    bool resolve_code_xrefs) {
    if (module_range.empty() || min_length == 0) {
        return fail(ErrorCode::InvalidArgument, "BinaryExplorer::scan_strings");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();

        std::unordered_map<std::uint64_t, std::vector<Address>> xref_map;
        if (resolve_code_xrefs) {
            for_each_readable_chunk(
                reader,
                module_range,
                16,
                [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                    if (!is_exec) {
                        return;
                    }
                    if (ptr_size == 8) {
                        for (std::size_t i = 0; i + 7 <= b.size(); ++i) {
                            const auto rex = static_cast<std::uint8_t>(b[i]);
                            const auto op = static_cast<std::uint8_t>(b[i + 1]);
                            const auto modrm = static_cast<std::uint8_t>(b[i + 2]);
                            if ((rex == 0x48u || rex == 0x4Cu) && op == 0x8Du &&
                                (modrm & 0xC7u) == 0x05u) {
                                std::int32_t disp = 0;
                                std::memcpy(&disp, b.data() + i + 3, 4);
                                const std::uint64_t ins_va = chunk_addr.value() + i;
                                const std::uint64_t target_va = static_cast<std::uint64_t>(
                                    static_cast<std::int64_t>(ins_va + 7) + disp);
                                if (module_range.contains(Address{target_va})) {
                                    xref_map[target_va].push_back(Address{ins_va});
                                }
                            }
                        }
                    } else {
                        for (std::size_t i = 0; i + 5 <= b.size(); ++i) {
                            const auto op = static_cast<std::uint8_t>(b[i]);
                            if (op == 0x68u || (op >= 0xB8u && op <= 0xBFu)) {
                                std::uint32_t imm = 0;
                                std::memcpy(&imm, b.data() + i + 1, 4);
                                if (module_range.contains(Address{imm})) {
                                    xref_map[imm].push_back(Address{chunk_addr.value() + i});
                                }
                            }
                        }
                    }
                });
        }

        std::vector<DiscoveredString> strings;
        for_each_readable_chunk(
            reader,
            module_range,
            0,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool) {
                std::size_t i = 0;
                while (i < b.size()) {
                    const char c = static_cast<char>(b[i]);
                    if (is_printable_ascii(c)) {
                        const std::size_t start = i;
                        while (i < b.size() && is_printable_ascii(static_cast<char>(b[i])) &&
                               (i - start) < 512) {
                            ++i;
                        }
                        if (i < b.size() && b[i] == std::byte{0} && (i - start) >= min_length) {
                            std::string val(reinterpret_cast<const char*>(b.data() + start),
                                            i - start);
                            const Address str_addr{chunk_addr.value() + start};
                            DiscoveredString ds{};
                            ds.is_source_path = looks_like_source_path(val);
                            ds.value = std::move(val);
                            ds.address = str_addr;
                            if (auto rva = module_range.to_rva(str_addr)) {
                                ds.rva = *rva;
                            }
                            if (resolve_code_xrefs) {
                                if (auto it = xref_map.find(str_addr.value());
                                    it != xref_map.end()) {
                                    ds.code_xrefs = it->second;
                                }
                            }
                            strings.push_back(std::move(ds));
                        }
                    }
                    ++i;
                }
            });

        return strings;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "BinaryExplorer::scan_strings");
    }
}

Result<std::vector<DiscoveredFunction>> BinaryExplorer::discover_functions(
    const Process& process,
    AddressRange module_range,
    const PeImage* pe) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "BinaryExplorer::discover_functions");
    }

    try {
        std::map<std::uint64_t, DiscoveredFunction> fn_map;
        const Address mod_base = module_range.begin();

        if (pe != nullptr) {
            for (const auto& pf : pe->exception_functions()) {
                auto va = mod_base.add_rva(pf.begin_rva);
                if (!va || !module_range.contains(*va)) {
                    continue;
                }
                DiscoveredFunction df{};
                df.address = *va;
                df.rva = pf.begin_rva;
                df.size = pf.size();
                df.from_pdata = true;
                fn_map[va->value()] = std::move(df);
            }
        }

        // Scan executable sections for E8 rel32 call instructions to discover non-pdata functions & call graph
        MemoryReader reader{process};
        for_each_readable_chunk(
            reader,
            module_range,
            8,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (!is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + 5 <= b.size(); ++i) {
                    if (b[i] == std::byte{0xE8}) {
                        std::int32_t rel = 0;
                        std::memcpy(&rel, b.data() + i + 1, 4);
                        const std::uint64_t call_va = chunk_addr.value() + i;
                        const std::uint64_t target_va = static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(call_va + 5) + rel);
                        const Address target_addr{target_va};
                        if (!module_range.contains(target_addr)) {
                            continue;
                        }
                        auto target_exec = reader.is_executable(AddressRange{target_addr, 1});
                        if (!target_exec || !*target_exec) {
                            continue;
                        }

                        auto& target_fn = fn_map[target_va];
                        if (target_fn.address.is_null()) {
                            target_fn.address = target_addr;
                            if (auto rva = module_range.to_rva(target_addr)) {
                                target_fn.rva = *rva;
                            }
                        }
                        target_fn.callers.push_back(Address{call_va});

                        auto it = fn_map.upper_bound(call_va);
                        if (it != fn_map.begin()) {
                            --it;
                            if (it->second.size == 0 || call_va < (it->first + it->second.size)) {
                                it->second.callees.push_back(target_addr);
                            }
                        }
                    }
                }
            });

        std::vector<DiscoveredFunction> out;
        out.reserve(fn_map.size());
        for (auto& [_, fn] : fn_map) {
            out.push_back(std::move(fn));
        }
        return out;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "BinaryExplorer::discover_functions");
    }
}

Result<ReconstructedStruct> BinaryExplorer::reconstruct_struct(
    const Process& process,
    AddressRange function_range,
    std::string_view name_hint) {
    if (function_range.empty() || function_range.size() > 65536) {
        return fail(ErrorCode::InvalidArgument, "BinaryExplorer::reconstruct_struct");
    }

    MemoryReader reader{process};
    auto bytes_res =
        reader.read_bytes(function_range.begin(), static_cast<std::size_t>(function_range.size()));
    if (!bytes_res) {
        return std::unexpected(bytes_res.error());
    }

    const auto& code = *bytes_res;
    std::map<std::size_t, InferredField> field_map;

    auto record_access = [&](std::int32_t disp,
                             std::size_t access_size,
                             InferredFieldKind kind,
                             bool is_write) {
        if (disp < 0 || disp > 0x4000) {
            return;
        }
        const auto off = static_cast<std::size_t>(disp);
        auto& f = field_map[off];
        if (f.access_count == 1 && !f.is_read && !f.is_written) {
            // Newly inserted
            f.offset = off;
            f.size = access_size;
            f.kind = (off == 0 && kind == InferredFieldKind::UInt64OrPointer)
                         ? InferredFieldKind::VTablePointer
                         : kind;
            f.access_count = 1;
        } else {
            ++f.access_count;
            if (access_size > f.size) {
                f.size = access_size;
            }
            if (kind == InferredFieldKind::Float32) {
                f.kind = InferredFieldKind::Float32;
            }
        }
        if (is_write) {
            f.is_written = true;
        } else {
            f.is_read = true;
        }
    };

    // Track registers and stack slots that currently hold `this`. MSVC/clang-cl
    // frequently spill RCX to [rsp+disp] and reload it into another register
    // before accessing members; tracking only a single register misses those
    // accesses (and is especially visible in small optimized functions).
    std::array<bool, 16> this_registers{};
    this_registers[1] = true; // RCX / ECX is the default `this` argument register.
    std::unordered_set<std::int64_t> this_stack_slots;
    std::int64_t stack_delta = 0; // RSP relative to its value at function entry.
    const std::int64_t pointer_size = process.pointer_size();

    for (std::size_t i = 0; i < code.size(); ++i) {
        const auto byte_at = [&](std::size_t at) {
            return static_cast<std::uint8_t>(code[at]);
        };

        // Track simple push/pop stack movement used by compiler-generated
        // prologues. This keeps stack-slot identities stable across the frame.
        const std::uint8_t first = byte_at(i);
        if (first >= 0x50u && first <= 0x57u) {
            stack_delta -= pointer_size;
            continue;
        }
        if (first >= 0x58u && first <= 0x5Fu) {
            stack_delta += pointer_size;
            continue;
        }

        {
        std::size_t op_idx = i;
        std::uint8_t rex = 0;
        if (first >= 0x40u && first <= 0x4Fu && i + 1 < code.size()) {
            rex = first;
            op_idx = i + 1;
        }
        if (op_idx + 1 >= code.size()) {
            continue;
        }

        const std::uint8_t op = byte_at(op_idx);
        const std::uint8_t modrm = byte_at(op_idx + 1);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6) & 0x03u);
        const std::uint8_t reg_low = static_cast<std::uint8_t>((modrm >> 3) & 0x07u);
        const std::uint8_t rm_low = static_cast<std::uint8_t>(modrm & 0x07u);
        const std::uint8_t reg = static_cast<std::uint8_t>(reg_low | ((rex & 0x04u) ? 8u : 0u));
        const std::uint8_t rm = static_cast<std::uint8_t>(rm_low | ((rex & 0x01u) ? 8u : 0u));

        // `sub rsp, imm8/imm32` and `add rsp, imm8/imm32` adjust the stack
        // address used to key saved `this` pointers.
        if ((op == 0x83u || op == 0x81u) && mod == 3u && rm_low == 4u &&
            (reg_low == 0u || reg_low == 5u)) {
            const std::size_t immediate_size = (op == 0x83u) ? 1u : 4u;
            if (op_idx + 2u + immediate_size <= code.size()) {
                std::int64_t amount = 0;
                if (immediate_size == 1u) {
                    amount = static_cast<std::int8_t>(byte_at(op_idx + 2u));
                } else {
                    std::int32_t imm32 = 0;
                    std::memcpy(&imm32, code.data() + op_idx + 2u, sizeof(imm32));
                    amount = imm32;
                }
                if (reg_low == 5u) {
                    stack_delta -= amount;
                } else {
                    stack_delta += amount;
                }
                i = op_idx + 1u + immediate_size;
                continue;
            }
        }

        // Handle MOV register/register and MOV register/[memory] variants.
        // The latter also models stack spills/reloads of the `this` pointer.
        if (op == 0x89u || op == 0x8Bu) {
            if (mod == 3u) {
                const std::uint8_t destination = (op == 0x89u) ? rm : reg;
                const std::uint8_t source = (op == 0x89u) ? reg : rm;
                if (destination < this_registers.size() && source < this_registers.size()) {
                    this_registers[destination] = this_registers[source];
                }
                i = op_idx + 1u;
                continue;
            }

            std::size_t cursor = op_idx + 2u;
            bool has_sib = false;
            std::uint8_t base_reg = rm;
            std::uint8_t index_reg = 0xFFu;
            if (rm_low == 4u) {
                if (cursor >= code.size()) {
                    continue;
                }
                has_sib = true;
                const std::uint8_t sib = byte_at(cursor++);
                const std::uint8_t base_low = static_cast<std::uint8_t>(sib & 0x07u);
                const std::uint8_t index_low = static_cast<std::uint8_t>((sib >> 3) & 0x07u);
                base_reg = static_cast<std::uint8_t>(base_low | ((rex & 0x01u) ? 8u : 0u));
                if (index_low != 4u || (rex & 0x02u) != 0u) {
                    index_reg = static_cast<std::uint8_t>(index_low | ((rex & 0x02u) ? 8u : 0u));
                }
            }

            std::int32_t displacement = 0;
            if (mod == 1u) {
                if (cursor >= code.size()) {
                    continue;
                }
                displacement = static_cast<std::int8_t>(byte_at(cursor++));
            } else if (mod == 2u || (mod == 0u && has_sib && (base_reg & 0x07u) == 5u)) {
                if (cursor + sizeof(displacement) > code.size()) {
                    continue;
                }
                std::memcpy(&displacement, code.data() + cursor, sizeof(displacement));
                cursor += sizeof(displacement);
            }

            const bool is_rsp_slot = has_sib && base_reg == 4u && index_reg == 0xFFu;
            if (is_rsp_slot) {
                const std::int64_t slot = stack_delta + displacement;
                if (op == 0x89u) {
                    if (reg < this_registers.size() && this_registers[reg]) {
                        this_stack_slots.insert(slot);
                    } else {
                        this_stack_slots.erase(slot);
                    }
                } else {
                    if (reg < this_registers.size()) {
                        this_registers[reg] = this_stack_slots.contains(slot);
                    }
                }
                i = cursor - 1u;
                continue;
            }

            // A MOV using a tracked `this` register as its base is a member
            // access. Record it here and update the destination register state
            // after recording (e.g. `mov eax, [rax+10h]` reads a field, then
            // overwrites EAX/RAX so it no longer contains `this`).
            if (!has_sib && rm < this_registers.size() && this_registers[rm] &&
                (mod == 1u || mod == 2u)) {
                const std::size_t access_size = (rex & 0x08u) ? 8u : 4u;
                record_access(displacement, access_size,
                              access_size == 8u ? InferredFieldKind::UInt64OrPointer
                                               : InferredFieldKind::Int32,
                              op == 0x89u);
            }
            if (op == 0x8Bu && reg < this_registers.size()) {
                this_registers[reg] = false;
            }
            i = cursor - 1u;
            continue;
        }
        }

        // Check SSE float movss: F3 0F 10 /r (read) or F3 0F 11 /r (write)
        if (i + 4 <= code.size() && code[i] == std::byte{0xF3} &&
            code[i + 1] == std::byte{0x0F} &&
            (code[i + 2] == std::byte{0x10} || code[i + 2] == std::byte{0x11})) {
            const bool is_write = (code[i + 2] == std::byte{0x11});
            const auto modrm = static_cast<std::uint8_t>(code[i + 3]);
            const auto mod = static_cast<std::uint8_t>((modrm >> 6) & 0x03u);
            const auto rm = static_cast<std::uint8_t>(modrm & 0x07u);
            if (rm < this_registers.size() && this_registers[rm]) {
                if (mod == 1u && i + 5 <= code.size()) {
                    const auto disp8 = static_cast<std::int8_t>(code[i + 4]);
                    record_access(disp8, 4, InferredFieldKind::Float32, is_write);
                    i += 4;
                    continue;
                } else if (mod == 2u && i + 8 <= code.size()) {
                    std::int32_t disp32 = 0;
                    std::memcpy(&disp32, code.data() + i + 4, 4);
                    record_access(disp32, 4, InferredFieldKind::Float32, is_write);
                    i += 7;
                    continue;
                }
            }
        }

        // Check REX.W prefix (0x48)
        bool has_rex_w = false;
        std::size_t op_idx = i;
        if (code[op_idx] == std::byte{0x48} && op_idx + 1 < code.size()) {
            has_rex_w = true;
            ++op_idx;
        }

        if (op_idx + 1 >= code.size()) {
            continue;
        }

        const auto op = static_cast<std::uint8_t>(code[op_idx]);
        const auto modrm = static_cast<std::uint8_t>(code[op_idx + 1]);
        const auto mod = static_cast<std::uint8_t>((modrm >> 6) & 0x03u);
        const auto rm = static_cast<std::uint8_t>(modrm & 0x07u);

        if (rm >= this_registers.size() || !this_registers[rm]) {
            continue;
        }
        if (mod != 1u && mod != 2u) {
            continue;
        }

        bool matched_op = false;
        bool is_write = false;
        std::size_t f_size = 4;
        InferredFieldKind f_kind = InferredFieldKind::Int32;

        if (op == 0x8Bu || op == 0x89u || op == 0x03u || op == 0x01u || op == 0x3Bu || op == 0x39u) {
            matched_op = true;
            is_write = (op == 0x89u || op == 0x01u);
            f_size = has_rex_w ? 8 : 4;
            f_kind = has_rex_w ? InferredFieldKind::UInt64OrPointer : InferredFieldKind::Int32;
        } else if (op == 0x8Au || op == 0x88u || op == 0x80u) {
            matched_op = true;
            is_write = (op == 0x88u);
            f_size = 1;
            f_kind = InferredFieldKind::UInt8;
        } else if (op == 0xC7u && ((modrm >> 3) & 0x07u) == 0u) {
            matched_op = true;
            is_write = true;
            f_size = 4;
            f_kind = InferredFieldKind::Int32;
        } else if (op == 0xC6u && ((modrm >> 3) & 0x07u) == 0u) {
            matched_op = true;
            is_write = true;
            f_size = 1;
            f_kind = InferredFieldKind::UInt8;
        }

        if (!matched_op) {
            continue;
        }

        if (mod == 1u && op_idx + 2 < code.size()) {
            const auto disp8 = static_cast<std::int8_t>(code[op_idx + 2]);
            record_access(disp8, f_size, f_kind, is_write);
        } else if (mod == 2u && op_idx + 5 < code.size()) {
            std::int32_t disp32 = 0;
            std::memcpy(&disp32, code.data() + op_idx + 2, 4);
            record_access(disp32, f_size, f_kind, is_write);
        }
    }

    ReconstructedStruct result{};
    result.name_hint = std::string(name_hint);
    for (const auto& [off, field] : field_map) {
        result.fields.push_back(field);
        const std::size_t end_off = off + field.size;
        if (end_off > result.estimated_size) {
            result.estimated_size = end_off;
        }
    }
    return result;
}

Result<std::vector<DiscoveredInstance>> BinaryExplorer::find_instances(
    const Process& process,
    AddressRange search_range,
    const RttiCatalog& catalog,
    std::string_view class_filter) {
    if (search_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "BinaryExplorer::find_instances");
    }

    try {
        std::unordered_map<std::uint64_t, const RttiClassDescriptor*> vtable_map;
        for (const auto& c : catalog.classes()) {
            if (!class_filter.empty() && c.demangled_name != class_filter &&
                c.mangled_name != class_filter) {
                continue;
            }
            vtable_map[c.vftable_address.value()] = &c;
        }

        std::vector<DiscoveredInstance> instances;
        if (vtable_map.empty()) {
            return instances;
        }

        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        for_each_readable_chunk(
            reader,
            search_range,
            0,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool) {
                for (std::size_t i = 0; i + ptr_size <= b.size(); i += ptr_size) {
                    std::uint64_t candidate_vptr = 0;
                    if (ptr_size == 8) {
                        std::memcpy(&candidate_vptr, b.data() + i, 8);
                    } else {
                        std::uint32_t v32 = 0;
                        std::memcpy(&v32, b.data() + i, 4);
                        candidate_vptr = v32;
                    }
                    if (auto it = vtable_map.find(candidate_vptr); it != vtable_map.end()) {
                        const Address inst_addr{chunk_addr.value() + i};
                        if (inst_addr == it->second->vftable_address) {
                            continue;
                        }
                        instances.push_back(DiscoveredInstance{
                            .instance_address = inst_addr,
                            .vftable_address = it->second->vftable_address,
                            .class_name = it->second->demangled_name,
                            .type_id = it->second->type_id,
                        });
                    }
                }
            });

        return instances;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "BinaryExplorer::find_instances");
    }
}

Result<std::vector<DissectedSlot>> BinaryExplorer::dissect_memory(
    const Process& process,
    AddressRange module_range,
    Address object_address,
    std::size_t byte_count,
    const RttiCatalog* catalog) {
    if (object_address.is_null() || byte_count == 0 || byte_count > 16384) {
        return fail(ErrorCode::InvalidArgument, "BinaryExplorer::dissect_memory");
    }

    MemoryReader reader{process};
    auto bytes_res = reader.read_bytes(object_address, byte_count);
    if (!bytes_res) {
        return std::unexpected(bytes_res.error());
    }

    const auto& b = *bytes_res;
    const std::uint8_t ptr_size = process.pointer_size();
    std::vector<DissectedSlot> slots;

    for (std::size_t off = 0; off + 4 <= b.size();) {
        DissectedSlot slot{};
        slot.offset = off;

        // First check if aligned pointer slot holds a valid pointer or vtable
        if ((off % ptr_size) == 0 && (off + ptr_size) <= b.size()) {
            std::uint64_t ptr_val = 0;
            if (ptr_size == 8) {
                std::memcpy(&ptr_val, b.data() + off, 8);
            } else {
                std::uint32_t p32 = 0;
                std::memcpy(&p32, b.data() + off, 4);
                ptr_val = p32;
            }
            slot.raw_u64 = ptr_val;

            const Address target{ptr_val};
            if (!target.is_null()) {
                if (catalog != nullptr) {
                    for (const auto& c : catalog->classes()) {
                        if (c.vftable_address == target) {
                            slot.kind = MemorySlotKind::VTableInstance;
                            slot.resolved_class_name = c.demangled_name;
                            slots.push_back(std::move(slot));
                            off += ptr_size;
                            goto next_slot;
                        }
                    }
                }
                auto is_r = reader.is_readable(AddressRange{target, 1});
                if (is_r && *is_r) {
                    auto is_x = reader.is_executable(AddressRange{target, 1});
                    if (is_x && *is_x) {
                        slot.kind = MemorySlotKind::PointerToCode;
                        slots.push_back(std::move(slot));
                        off += ptr_size;
                        goto next_slot;
                    }
                    if (auto str = reader.read_cstring(target, 64); str && str->size() >= 3) {
                        bool printable = true;
                        for (const char ch : *str) {
                            if (!is_printable_ascii(ch)) {
                                printable = false;
                                break;
                            }
                        }
                        if (printable) {
                            slot.kind = MemorySlotKind::PointerToAsciiString;
                            slot.string_preview = std::move(*str);
                            slots.push_back(std::move(slot));
                            off += ptr_size;
                            goto next_slot;
                        }
                    }
                    if (module_range.contains(target) || ptr_val >= 0x10000ULL) {
                        slot.kind = MemorySlotKind::PointerToData;
                        slots.push_back(std::move(slot));
                        off += ptr_size;
                        goto next_slot;
                    }
                }
            }
        }

        // Interpret as 4-byte scalar (Zero, Float32, or Integer32)
        {
            std::int32_t i32 = 0;
            float f32 = 0.0f;
            std::uint32_t u32 = 0;
            std::memcpy(&i32, b.data() + off, 4);
            std::memcpy(&f32, b.data() + off, 4);
            std::memcpy(&u32, b.data() + off, 4);
            slot.raw_u64 = u32;
            slot.i32_value = i32;
            slot.f32_value = f32;

            if (u32 == 0) {
                slot.kind = MemorySlotKind::Zero;
            } else if (std::isfinite(f32) && std::fabs(f32) >= 0.0001f &&
                       std::fabs(f32) <= 1000000.0f && (u32 & 0x7F800000u) != 0) {
                slot.kind = MemorySlotKind::Float32;
            } else {
                slot.kind = MemorySlotKind::Integer32;
            }
            slots.push_back(std::move(slot));
            off += 4;
        }
    next_slot:;
    }

    return slots;
}

} // namespace tessera::rtti
