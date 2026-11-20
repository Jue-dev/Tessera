#include "tessera/rtti/python_bridge.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_map>

#include "python_bridge_detail.hpp"

namespace tessera::rtti {

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

} // namespace tessera::rtti
