#include "tessera/rtti/python_bridge.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <new>
#include <unordered_map>
#include <unordered_set>

#include "tessera/memory/memory_reader.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/utility/string.hpp"

#include "readable_chunks.hpp"

namespace tessera::rtti {



std::size_t PyMemberEntry::inferred_field_size(std::uint8_t ptr_size) const noexcept {
    switch (type) {
        case 7:  // T_CHAR
        case 8:  // T_BYTE
        case 9:  // T_UBYTE
        case 14: // T_BOOL
            return 1;
        case 0:  // T_SHORT
        case 10: // T_USHORT
            return 2;
        case 1:  // T_INT
        case 2:  // T_LONG (32-bit on Windows LLP64)
        case 3:  // T_FLOAT
        case 11: // T_UINT
        case 12: // T_ULONG
            return 4;
        case 4:  // T_DOUBLE
        case 17: // T_LONGLONG
        case 18: // T_ULONGLONG
            return 8;
        case 5:  // T_STRING
        case 6:  // T_OBJECT
        case 16: // T_OBJECT_EX
        case 19: // T_PYSSIZET
            return ptr_size;
        default:
            return 4;
    }
}

Result<PyMethodEntry> PythonBridgeCatalog::find_method(std::string_view name_or_qualified) const {
    if (name_or_qualified.empty()) {
        return fail(ErrorCode::InvalidArgument, "PythonBridgeCatalog::find_method");
    }
    const auto dot_pos = name_or_qualified.find('.');
    if (dot_pos != std::string_view::npos) {
        const std::string_view mod_part = name_or_qualified.substr(0, dot_pos);
        const std::string_view fn_part = name_or_qualified.substr(dot_pos + 1);
        for (const auto& tbl : method_tables) {
            if (tbl.inferred_module_name == mod_part) {
                for (const auto& m : tbl.methods) {
                    if (m.name == fn_part) {
                        return m;
                    }
                }
            }
        }
    }
    for (const auto& tbl : method_tables) {
        for (const auto& m : tbl.methods) {
            if (m.name == name_or_qualified) {
                return m;
            }
        }
    }
    return fail(ErrorCode::NotFound, "PythonBridgeCatalog::find_method");
}

Status PythonBridgeCatalog::export_to_registry(reflection::TypeRegistry& registry) const {
    for (std::size_t ti = 0; ti < method_tables.size(); ++ti) {
        const auto& tbl = method_tables[ti];
        const std::string mod_name =
            !tbl.inferred_module_name.empty()
                ? std::format("python::{}", tbl.inferred_module_name)
                : std::format("python::module_{:X}", tbl.table_rva.value());

        reflection::DynamicTypeBuilder builder(mod_name, reflection::TypeKind::PythonModule);
        for (const auto& m : tbl.methods) {
            builder.method(reflection::MethodInfo{
                .name = m.name,
                .kind = reflection::MethodKind::PythonCFunction,
                .rva = m.cpp_function_rva,
                .address = m.cpp_function_address,
                .python_doc = m.doc,
                .python_flags = m.flags,
            });
        }
        auto st = registry.upsert_type(builder.build());
        if (!st) {
            return st;
        }
    }

    if (!member_entries.empty() || !getset_entries.empty()) {
        reflection::DynamicTypeBuilder obj_builder("python::ExposedObject",
                                                   reflection::TypeKind::PythonType);
        std::size_t max_end = 0;
        for (const auto& mem : member_entries) {
            const std::size_t fsz = mem.inferred_field_size(8);
            if (mem.offset + fsz > max_end) {
                max_end = mem.offset + fsz;
            }
            obj_builder.field(reflection::FieldInfo{
                .name = mem.name,
                .type_id = reflection::TypeId::from_name("python_member"),
                .offset = mem.offset,
                .size = fsz,
                .flags = reflection::FieldFlags::PythonExposed,
            });
        }
        obj_builder.size(max_end);
        for (const auto& gs : getset_entries) {
            if (!gs.getter_address.is_null()) {
                obj_builder.method(reflection::MethodInfo{
                    .name = std::format("get_{}", gs.name),
                    .kind = reflection::MethodKind::PythonGetter,
                    .address = gs.getter_address,
                    .python_doc = gs.doc,
                });
            }
            if (!gs.setter_address.is_null()) {
                obj_builder.method(reflection::MethodInfo{
                    .name = std::format("set_{}", gs.name),
                    .kind = reflection::MethodKind::PythonSetter,
                    .address = gs.setter_address,
                    .python_doc = gs.doc,
                });
            }
        }
        auto st = registry.upsert_type(obj_builder.build());
        if (!st) {
            return st;
        }
    }

    return ok();
}

Result<PythonBridgeCatalog> PythonBridgeScanner::discover_all(
    const Process& process,
    AddressRange module_range,
    const PeImage* pe) {
    auto env_res = detect_environment(process, module_range, pe);
    if (!env_res) {
        return std::unexpected(env_res.error());
    }
    auto inittab_res = scan_inittab(process, module_range);
    if (!inittab_res) {
        return std::unexpected(inittab_res.error());
    }
    auto methods_res = scan_method_tables(process, module_range);
    if (!methods_res) {
        return std::unexpected(methods_res.error());
    }
    auto members_res = scan_member_tables(process, module_range);
    if (!members_res) {
        return std::unexpected(members_res.error());
    }
    auto getset_res = scan_getset_tables(process, module_range);
    if (!getset_res) {
        return std::unexpected(getset_res.error());
    }
    auto types_res = scan_type_objects(process, module_range);
    if (!types_res) {
        return std::unexpected(types_res.error());
    }

    PythonBridgeCatalog cat{};
    cat.environment = std::move(*env_res);
    cat.inittab_entries = std::move(*inittab_res);
    cat.method_tables = std::move(*methods_res);
    cat.member_entries = std::move(*members_res);

    // Filter out false-positive single-element PyGetSetEntry candidates that
    // overlap with _inittab (where {name, initfunc, 0, 0, 0} shares the exact
    // 5-pointer prefix layout of a read-only PyGetSetDef entry).
    std::unordered_set<std::uint64_t> claimed_addresses;
    for (const auto& ite : cat.inittab_entries) {
        claimed_addresses.insert(ite.entry_address.value());
    }
    for (const auto& tbl : cat.method_tables) {
        for (const auto& m : tbl.methods) {
            claimed_addresses.insert(m.entry_address.value());
        }
    }
    for (const auto& mem : cat.member_entries) {
        claimed_addresses.insert(mem.entry_address.value());
    }
    for (auto& gs : *getset_res) {
        if (!claimed_addresses.contains(gs.entry_address.value())) {
            cat.getset_entries.push_back(std::move(gs));
        }
    }
    cat.type_objects = std::move(*types_res);

    Address static_init_mod{};
    link_tables_to_modules(
        process, module_range, cat.method_tables, cat.inittab_entries, &static_init_mod);
    if (!static_init_mod.is_null()) {
        cat.environment.static_init_module_address = static_init_mod;
    }

    // Structural C-API tables prove that the module exposes CPython APIs, but do
    // not prove that CPython itself is statically linked. In particular, an ELF
    // extension/host may link to shared libpython, and a PE may be inspected
    // without its import metadata. Keep deployment unknown unless core-runtime
    // fingerprints (or an explicit PE import above) establish it.
    const bool has_cpython_tables =
        !cat.inittab_entries.empty() || !cat.method_tables.empty() ||
        !cat.member_entries.empty() || !cat.getset_entries.empty() ||
        !cat.type_objects.empty();
    if (cat.environment.framework == PythonFramework::Unknown && has_cpython_tables) {
        cat.environment.framework = PythonFramework::CPythonCAPI;
    }

    return cat;
}

} // namespace tessera::rtti
