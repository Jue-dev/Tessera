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

} // namespace tessera::rtti
