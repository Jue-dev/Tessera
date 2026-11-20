#include "tessera/rtti/python_bridge.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <unordered_map>
#include <unordered_set>

#include "tessera/memory/memory_reader.hpp"
#include "python_bridge_detail.hpp"

namespace tessera::rtti {

Result<std::vector<PyInittabEntry>> PythonBridgeScanner::scan_inittab(
    const Process& process,
    AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::scan_inittab");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        const std::size_t entry_size = static_cast<std::size_t>(ptr_size) * 2u;

        std::vector<PyInittabEntry> results;
        std::unordered_set<std::uint64_t> visited;

        for_each_readable_chunk(
            reader,
            module_range,
            64,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + entry_size * 2 <= b.size(); i += ptr_size) {
                    const std::uint64_t cur_va = chunk_addr.value() + i;
                    if (visited.contains(cur_va)) {
                        continue;
                    }

                    std::vector<PyInittabEntry> run;
                    std::size_t cursor = i;
                    bool terminated_by_null = false;

                    while (cursor + entry_size <= b.size()) {
                        const std::uint64_t name_ptr = read_ptr_at(b, cursor, ptr_size);
                        const std::uint64_t init_ptr = read_ptr_at(b, cursor + ptr_size, ptr_size);

                        if (name_ptr == 0 && init_ptr == 0) {
                            terminated_by_null = true;
                            break;
                        }
                        const Address name_addr{name_ptr};
                        const Address init_addr{init_ptr};
                        if (!module_range.contains(name_addr) ||
                            !module_range.contains(init_addr)) {
                            break;
                        }
                        auto is_x = reader.is_executable(AddressRange{init_addr, 1});
                        if (!is_x || !*is_x) {
                            break;
                        }
                        auto mod_str = reader.read_cstring(name_addr, 64);
                        if (!mod_str || !is_python_identifier(*mod_str, false)) {
                            break;
                        }

                        PyInittabEntry entry{};
                        entry.module_name = std::move(*mod_str);
                        entry.init_function_address = init_addr;
                        if (auto rva = module_range.to_rva(init_addr)) {
                            entry.init_function_rva = *rva;
                        }
                        entry.entry_address = Address{chunk_addr.value() + cursor};
                        run.push_back(std::move(entry));
                        cursor += entry_size;
                    }

                    if (terminated_by_null && !run.empty()) {
                        for (std::size_t k = i; k <= cursor; k += ptr_size) {
                            visited.insert(chunk_addr.value() + k);
                        }
                        for (auto& e : run) {
                            results.push_back(std::move(e));
                        }
                    }
                }
            });

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PythonBridgeScanner::scan_inittab");
    }
}

Result<std::vector<PyMethodTable>> PythonBridgeScanner::scan_method_tables(
    const Process& process,
    AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::scan_method_tables");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        const std::size_t entry_size = (ptr_size == 8) ? 32u : 16u;

        std::vector<PyMethodTable> tables;
        std::unordered_set<std::uint64_t> visited;

        for_each_readable_chunk(
            reader,
            module_range,
            256,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + entry_size * 2 <= b.size(); i += ptr_size) {
                    const std::uint64_t table_va = chunk_addr.value() + i;
                    if (visited.contains(table_va)) {
                        continue;
                    }

                    std::vector<PyMethodEntry> methods;
                    std::size_t cursor = i;
                    bool sentinel_ok = false;

                    while (cursor + entry_size <= b.size()) {
                        std::uint64_t name_ptr = 0;
                        std::uint64_t meth_ptr = 0;
                        std::uint32_t flags = 0;
                        std::uint32_t pad = 0;
                        std::uint64_t doc_ptr = 0;

                        if (ptr_size == 8) {
                            std::memcpy(&name_ptr, b.data() + cursor + 0, 8);
                            std::memcpy(&meth_ptr, b.data() + cursor + 8, 8);
                            std::memcpy(&flags, b.data() + cursor + 16, 4);
                            std::memcpy(&pad, b.data() + cursor + 20, 4);
                            std::memcpy(&doc_ptr, b.data() + cursor + 24, 8);
                        } else {
                            std::uint32_t np = 0, mp = 0, dp = 0;
                            std::memcpy(&np, b.data() + cursor + 0, 4);
                            std::memcpy(&mp, b.data() + cursor + 4, 4);
                            std::memcpy(&flags, b.data() + cursor + 8, 4);
                            std::memcpy(&dp, b.data() + cursor + 12, 4);
                            name_ptr = np;
                            meth_ptr = mp;
                            doc_ptr = dp;
                        }

                        if (name_ptr == 0 && meth_ptr == 0) {
                            sentinel_ok = true;
                            break;
                        }

                        if (pad != 0 || !is_valid_meth_flags(flags)) {
                            break;
                        }

                        const Address name_addr{name_ptr};
                        const Address meth_addr{meth_ptr};
                        if (!module_range.contains(name_addr) ||
                            !module_range.contains(meth_addr)) {
                            break;
                        }

                        auto is_x = reader.is_executable(AddressRange{meth_addr, 1});
                        if (!is_x || !*is_x) {
                            break;
                        }

                        auto fn_name = reader.read_cstring(name_addr, 96);
                        if (!fn_name || !is_python_identifier(*fn_name, false)) {
                            break;
                        }

                        std::string doc_str;
                        if (doc_ptr != 0) {
                            if (!module_range.contains(Address{doc_ptr})) {
                                break;
                            }
                            if (auto ds = reader.read_cstring(Address{doc_ptr}, 256)) {
                                doc_str = std::move(*ds);
                            }
                        }

                        PyMethodEntry entry{};
                        entry.name = std::move(*fn_name);
                        entry.cpp_function_address = meth_addr;
                        if (auto rva = module_range.to_rva(meth_addr)) {
                            entry.cpp_function_rva = *rva;
                        }
                        entry.flags = flags;
                        entry.doc = std::move(doc_str);
                        entry.entry_address = Address{chunk_addr.value() + cursor};
                        methods.push_back(std::move(entry));

                        cursor += entry_size;
                    }

                    if (sentinel_ok && !methods.empty()) {
                        for (std::size_t k = i; k <= cursor; k += ptr_size) {
                            visited.insert(chunk_addr.value() + k);
                        }
                        PyMethodTable tbl{};
                        tbl.table_address = Address{table_va};
                        if (auto rva = module_range.to_rva(tbl.table_address)) {
                            tbl.table_rva = *rva;
                        }
                        tbl.methods = std::move(methods);
                        tables.push_back(std::move(tbl));
                    }
                }
            });

        return tables;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PythonBridgeScanner::scan_method_tables");
    }
}

void PythonBridgeScanner::link_tables_to_modules(
    const Process& process,
    AddressRange module_range,
    std::span<PyMethodTable> tables,
    std::span<const PyInittabEntry> inittab,
    Address* out_static_init_module) {
    if (tables.empty() || module_range.empty()) {
        return;
    }

    MemoryReader reader{process};
    const std::uint8_t ptr_size = process.pointer_size();

    std::unordered_map<std::uint64_t, PyMethodTable*> table_map;
    for (auto& t : tables) {
        table_map[t.table_address.value()] = &t;
    }

    // 1. Scan executable regions for code xrefs to each PyMethodTable address
    for_each_readable_chunk(
        reader,
        module_range,
        64,
        [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
            if (!is_exec) {
                return;
            }
            for (std::size_t i = 0; i + 7 <= b.size(); ++i) {
                std::uint64_t referenced_va = 0;
                std::size_t instr_len = 0;

                if (ptr_size == 8) {
                    const auto rex = static_cast<std::uint8_t>(b[i]);
                    const auto op = static_cast<std::uint8_t>(b[i + 1]);
                    const auto modrm = static_cast<std::uint8_t>(b[i + 2]);
                    if ((rex == 0x48u || rex == 0x4Cu) && op == 0x8Du &&
                        (modrm & 0xC7u) == 0x05u) {
                        std::int32_t disp = 0;
                        std::memcpy(&disp, b.data() + i + 3, 4);
                        const std::uint64_t ins_va = chunk_addr.value() + i;
                        referenced_va = static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(ins_va + 7) + disp);
                        instr_len = 7;
                    }
                } else {
                    const auto op = static_cast<std::uint8_t>(b[i]);
                    if (op == 0x68u || (op >= 0xB8u && op <= 0xBFu)) {
                        std::uint32_t imm = 0;
                        std::memcpy(&imm, b.data() + i + 1, 4);
                        referenced_va = imm;
                        instr_len = 5;
                    }
                }

                if (instr_len == 0) {
                    continue;
                }
                auto it = table_map.find(referenced_va);
                if (it == table_map.end()) {
                    continue;
                }

                PyMethodTable* tbl = it->second;
                const std::uint64_t ref_va = chunk_addr.value() + i;

                for (const auto& ite : inittab) {
                    const std::uint64_t fn_va = ite.init_function_address.value();
                    if (ref_va >= fn_va && ref_va < fn_va + 0x200u) {
                        tbl->init_function_address = ite.init_function_address;
                        tbl->inferred_module_name = ite.module_name;
                        break;
                    }
                }

                const std::size_t win_start = (i > 28) ? (i - 28) : 0;
                const std::size_t win_end = (std::min)(b.size(), i + 36);

                for (std::size_t w = win_start; w + 5 <= win_end; ++w) {
                    if (w == i) {
                        continue;
                    }
                    std::uint64_t cand_str_va = 0;
                    if (ptr_size == 8 && w + 7 <= win_end) {
                        const auto rex = static_cast<std::uint8_t>(b[w]);
                        const auto op = static_cast<std::uint8_t>(b[w + 1]);
                        const auto modrm = static_cast<std::uint8_t>(b[w + 2]);
                        if ((rex == 0x48u || rex == 0x4Cu) && op == 0x8Du &&
                            (modrm & 0xC7u) == 0x05u) {
                            std::int32_t disp = 0;
                            std::memcpy(&disp, b.data() + w + 3, 4);
                            const std::uint64_t w_va = chunk_addr.value() + w;
                            cand_str_va = static_cast<std::uint64_t>(
                                static_cast<std::int64_t>(w_va + 7) + disp);
                        }
                    } else if (ptr_size == 4) {
                        const auto op = static_cast<std::uint8_t>(b[w]);
                        if (op == 0x68u || (op >= 0xB8u && op <= 0xBFu)) {
                            std::uint32_t imm = 0;
                            std::memcpy(&imm, b.data() + w + 1, 4);
                            cand_str_va = imm;
                        }
                    }

                    if (cand_str_va != 0 && cand_str_va != referenced_va &&
                        module_range.contains(Address{cand_str_va}) &&
                        tbl->inferred_module_name.empty()) {
                        if (auto s = reader.read_cstring(Address{cand_str_va}, 64);
                            s && is_python_identifier(*s, false)) {
                            tbl->inferred_module_name = std::move(*s);
                        }
                    }

                    if (w >= i + instr_len && b[w] == std::byte{0xE8}) {
                        std::int32_t rel = 0;
                        std::memcpy(&rel, b.data() + w + 1, 4);
                        const std::uint64_t call_va = chunk_addr.value() + w;
                        const std::uint64_t callee_va = static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(call_va + 5) + rel);
                        if (module_range.contains(Address{callee_va})) {
                            tbl->register_call_target = Address{callee_va};
                            if (out_static_init_module != nullptr &&
                                out_static_init_module->is_null()) {
                                *out_static_init_module = Address{callee_va};
                            }
                            break;
                        }
                    }
                }
            }
        });
}

Result<std::vector<PyMemberEntry>> PythonBridgeScanner::scan_member_tables(
    const Process& process,
    AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::scan_member_tables");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        const std::size_t entry_size = (ptr_size == 8) ? 40u : 20u;

        std::vector<PyMemberEntry> results;
        std::unordered_set<std::uint64_t> visited;

        for_each_readable_chunk(
            reader,
            module_range,
            256,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + entry_size * 2 <= b.size(); i += ptr_size) {
                    const std::uint64_t cur_va = chunk_addr.value() + i;
                    if (visited.contains(cur_va)) {
                        continue;
                    }

                    std::vector<PyMemberEntry> run;
                    std::size_t cursor = i;
                    bool sentinel_ok = false;

                    while (cursor + entry_size <= b.size()) {
                        std::uint64_t name_ptr = 0;
                        std::int32_t m_type = 0;
                        std::int32_t pad0 = 0;
                        std::uint64_t m_offset = 0;
                        std::int32_t m_flags = 0;
                        std::int32_t pad1 = 0;
                        std::uint64_t doc_ptr = 0;

                        if (ptr_size == 8) {
                            std::memcpy(&name_ptr, b.data() + cursor + 0, 8);
                            std::memcpy(&m_type, b.data() + cursor + 8, 4);
                            std::memcpy(&pad0, b.data() + cursor + 12, 4);
                            std::memcpy(&m_offset, b.data() + cursor + 16, 8);
                            std::memcpy(&m_flags, b.data() + cursor + 24, 4);
                            std::memcpy(&pad1, b.data() + cursor + 28, 4);
                            std::memcpy(&doc_ptr, b.data() + cursor + 32, 8);
                        } else {
                            std::uint32_t np = 0, off32 = 0, dp = 0;
                            std::memcpy(&np, b.data() + cursor + 0, 4);
                            std::memcpy(&m_type, b.data() + cursor + 4, 4);
                            std::memcpy(&off32, b.data() + cursor + 8, 4);
                            std::memcpy(&m_flags, b.data() + cursor + 12, 4);
                            std::memcpy(&dp, b.data() + cursor + 16, 4);
                            name_ptr = np;
                            m_offset = off32;
                            doc_ptr = dp;
                        }

                        if (name_ptr == 0 && m_type == 0 && m_offset == 0) {
                            sentinel_ok = true;
                            break;
                        }

                        if (pad0 != 0 || pad1 != 0 || m_type < 0 || m_type > 20 ||
                            m_offset == 0 || m_offset > 0x10000ULL || m_flags < 0 || m_flags > 15) {
                            break;
                        }
                        const Address name_addr{name_ptr};
                        if (!module_range.contains(name_addr)) {
                            break;
                        }
                        auto is_x = reader.is_executable(AddressRange{name_addr, 1});
                        if (is_x && *is_x) {
                            break;
                        }
                        auto m_name = reader.read_cstring(name_addr, 64);
                        if (!m_name || !is_python_identifier(*m_name, false)) {
                            break;
                        }

                        std::string doc_str;
                        if (doc_ptr != 0) {
                            if (!module_range.contains(Address{doc_ptr})) {
                                break;
                            }
                            if (auto ds = reader.read_cstring(Address{doc_ptr}, 256)) {
                                doc_str = std::move(*ds);
                            }
                        }

                        PyMemberEntry entry{};
                        entry.name = std::move(*m_name);
                        entry.type = m_type;
                        entry.offset = static_cast<std::size_t>(m_offset);
                        entry.flags = m_flags;
                        entry.doc = std::move(doc_str);
                        entry.entry_address = Address{chunk_addr.value() + cursor};
                        run.push_back(std::move(entry));
                        cursor += entry_size;
                    }

                    if (sentinel_ok && !run.empty()) {
                        for (std::size_t k = i; k <= cursor; k += ptr_size) {
                            visited.insert(chunk_addr.value() + k);
                        }
                        for (auto& e : run) {
                            results.push_back(std::move(e));
                        }
                    }
                }
            });

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PythonBridgeScanner::scan_member_tables");
    }
}

Result<std::vector<PyGetSetEntry>> PythonBridgeScanner::scan_getset_tables(
    const Process& process,
    AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::scan_getset_tables");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        const std::size_t entry_size = static_cast<std::size_t>(ptr_size) * 5u;

        std::vector<PyGetSetEntry> results;
        std::unordered_set<std::uint64_t> visited;

        for_each_readable_chunk(
            reader,
            module_range,
            256,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + entry_size * 2 <= b.size(); i += ptr_size) {
                    const std::uint64_t cur_va = chunk_addr.value() + i;
                    if (visited.contains(cur_va)) {
                        continue;
                    }

                    std::vector<PyGetSetEntry> run;
                    std::size_t cursor = i;
                    bool sentinel_ok = false;

                    while (cursor + entry_size <= b.size()) {
                        const std::uint64_t name_ptr =
                            read_ptr_at(b, cursor + 0 * ptr_size, ptr_size);
                        const std::uint64_t get_ptr =
                            read_ptr_at(b, cursor + 1 * ptr_size, ptr_size);
                        const std::uint64_t set_ptr =
                            read_ptr_at(b, cursor + 2 * ptr_size, ptr_size);
                        const std::uint64_t doc_ptr =
                            read_ptr_at(b, cursor + 3 * ptr_size, ptr_size);
                        const std::uint64_t clos_ptr =
                            read_ptr_at(b, cursor + 4 * ptr_size, ptr_size);

                        if (name_ptr == 0 && get_ptr == 0 && set_ptr == 0) {
                            sentinel_ok = true;
                            break;
                        }
                        if (name_ptr == 0 || (get_ptr == 0 && set_ptr == 0)) {
                            break;
                        }

                        const Address name_addr{name_ptr};
                        if (!module_range.contains(name_addr)) {
                            break;
                        }
                        if (get_ptr != 0) {
                            const Address ga{get_ptr};
                            if (!module_range.contains(ga)) break;
                            auto is_x = reader.is_executable(AddressRange{ga, 1});
                            if (!is_x || !*is_x) break;
                        }
                        if (set_ptr != 0) {
                            const Address sa{set_ptr};
                            if (!module_range.contains(sa)) break;
                            auto is_x = reader.is_executable(AddressRange{sa, 1});
                            if (!is_x || !*is_x) break;
                        }

                        auto prop_name = reader.read_cstring(name_addr, 64);
                        if (!prop_name || !is_python_identifier(*prop_name, false)) {
                            break;
                        }

                        std::string doc_str;
                        if (doc_ptr != 0) {
                            if (!module_range.contains(Address{doc_ptr})) break;
                            if (auto ds = reader.read_cstring(Address{doc_ptr}, 256)) {
                                doc_str = std::move(*ds);
                            }
                        }

                        PyGetSetEntry entry{};
                        entry.name = std::move(*prop_name);
                        entry.getter_address = Address{get_ptr};
                        entry.setter_address = Address{set_ptr};
                        entry.doc = std::move(doc_str);
                        entry.closure = Address{clos_ptr};
                        entry.entry_address = Address{chunk_addr.value() + cursor};
                        run.push_back(std::move(entry));
                        cursor += entry_size;
                    }

                    if (sentinel_ok && !run.empty()) {
                        for (std::size_t k = i; k <= cursor; k += ptr_size) {
                            visited.insert(chunk_addr.value() + k);
                        }
                        for (auto& e : run) {
                            results.push_back(std::move(e));
                        }
                    }
                }
            });

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PythonBridgeScanner::scan_getset_tables");
    }
}

Result<std::vector<PyDiscoveredTypeObject>> PythonBridgeScanner::scan_type_objects(
    const Process& process,
    AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeScanner::scan_type_objects");
    }

    try {
        MemoryReader reader{process};
        const std::uint8_t ptr_size = process.pointer_size();
        const std::size_t tp_name_off = 3u * ptr_size;
        const std::size_t min_type_obj_size = 32u * ptr_size;

        std::vector<PyDiscoveredTypeObject> results;

        for_each_readable_chunk(
            reader,
            module_range,
            256,
            [&](Address chunk_addr, const std::vector<std::byte>& b, bool is_exec) {
                if (is_exec) {
                    return;
                }
                for (std::size_t i = 0; i + min_type_obj_size <= b.size(); i += ptr_size) {
                    const std::uint64_t refcnt = read_ptr_at(b, i, ptr_size);
                    const std::uint64_t ob_size = read_ptr_at(b, i + 2 * ptr_size, ptr_size);
                    const std::uint64_t tp_name_ptr = read_ptr_at(b, i + tp_name_off, ptr_size);
                    const std::uint64_t tp_basicsize = read_ptr_at(b, i + 4 * ptr_size, ptr_size);
                    const std::uint64_t tp_itemsize = read_ptr_at(b, i + 5 * ptr_size, ptr_size);

                    if (!is_plausible_python_refcount(refcnt) || ob_size != 0) {
                        continue;
                    }
                    if (tp_basicsize < 2u * ptr_size || tp_basicsize > 0x10000ULL ||
                        tp_itemsize > 0x1000ULL) {
                        continue;
                    }
                    const Address name_addr{tp_name_ptr};
                    if (!module_range.contains(name_addr)) {
                        continue;
                    }
                    auto tname = reader.read_cstring(name_addr, 96);
                    if (!tname || !is_python_identifier(*tname, true) ||
                        tname->find('.') == std::string::npos) {
                        continue;
                    }

                    // PyTypeObject keeps tp_methods / tp_members / tp_getset at
                    // pointer-sized slots 29, 30 and 31 in supported CPython
                    // layouts (the scanned 32-slot prefix includes all three).
                    const auto read_table_address = [&](std::size_t field_offset,
                                                        std::size_t minimum_size) {
                        const std::uint64_t table_ptr = read_ptr_at(b, i + field_offset, ptr_size);
                        if (table_ptr == 0) {
                            return Address{};
                        }
                        const auto readable = reader.is_readable(
                            AddressRange{Address{table_ptr}, minimum_size});
                        return (readable && *readable) ? Address{table_ptr} : Address{};
                    };

                    PyDiscoveredTypeObject obj{};
                    obj.type_name = std::move(*tname);
                    obj.basic_size = static_cast<std::size_t>(tp_basicsize);
                    obj.item_size = static_cast<std::size_t>(tp_itemsize);
                    obj.type_object_address = Address{chunk_addr.value() + i};
                    obj.methods_table_address = read_table_address(29u * ptr_size, 4u * ptr_size);
                    obj.members_table_address = read_table_address(30u * ptr_size, 5u * ptr_size);
                    obj.getset_table_address = read_table_address(31u * ptr_size, 5u * ptr_size);
                    results.push_back(std::move(obj));
                }
            });

        return results;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PythonBridgeScanner::scan_type_objects");
    }
}

} // namespace tessera::rtti
