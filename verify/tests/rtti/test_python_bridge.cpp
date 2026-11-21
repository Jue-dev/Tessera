#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/rtti/object_view.hpp"
#include "tessera/rtti/python_bridge.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/targets/target_profile_json.hpp"
#include "tessera/targets/target_runtime.hpp"

#include "rtti_test_helpers.hpp"

using namespace rtti_test_support;

TEST_CASE("PythonBridgeScanner discovers statically-embedded Python without python.dll",
          "[rtti][python]") {
    using namespace tessera;
    using namespace tessera::rtti;

    constexpr std::uint64_t kModBase = 0x140000000ULL;
    auto backend = std::make_shared<testing::FakeMemoryBackend>();

    // .text at +0x1000 (Executable)
    auto& text_reg =
        backend->map_region(Address{kModBase + 0x1000}, 0x2000, MemoryProtection::ExecuteRead);

    // C++ functions exposed to Python:
    // RVA 0x1100: net_SendChatPacket
    // RVA 0x1140: net_GetServerInfo
    // RVA 0x1180: chr_SetPosition
    // RVA 0x11C0: chr_GetName (getter)
    // RVA 0x1200: chr_SetName (setter)
    // RVA 0x1500: initchr() function referencing chr PyMethodDef table (RVA 0x3300) and "chr" (RVA 0x3060)
    //             and calling static Py_InitModule4 (RVA 0x1800)
    text_reg.storage[0x100] = std::byte{0xC3};
    text_reg.storage[0x140] = std::byte{0xC3};
    text_reg.storage[0x180] = std::byte{0xC3};
    text_reg.storage[0x1C0] = std::byte{0xC3};
    text_reg.storage[0x200] = std::byte{0xC3};
    text_reg.storage[0x800] = std::byte{0xC3}; // static Py_InitModule4 at RVA 0x1800

    // Write initchr() at RVA 0x1500 (offset 0x500 in .text):
    text_reg.storage[0x500] = std::byte{0x48};
    text_reg.storage[0x501] = std::byte{0x8D};
    text_reg.storage[0x502] = std::byte{0x0D};
    write_i32(text_reg.storage, 0x503, 0x3060 - 0x1507);

    text_reg.storage[0x507] = std::byte{0x48};
    text_reg.storage[0x508] = std::byte{0x8D};
    text_reg.storage[0x509] = std::byte{0x15};
    write_i32(text_reg.storage, 0x50A, 0x3300 - 0x150E);

    text_reg.storage[0x50E] = std::byte{0xE8};
    write_i32(text_reg.storage, 0x50F, 0x1800 - 0x1513);
    text_reg.storage[0x513] = std::byte{0xC3};

    // Write initnet() at RVA 0x1600 (offset 0x600 in .text) referenced by _inittab:
    text_reg.storage[0x600] = std::byte{0x48};
    text_reg.storage[0x601] = std::byte{0x8D};
    text_reg.storage[0x602] = std::byte{0x15};
    write_i32(text_reg.storage, 0x603, 0x3200 - 0x1607);
    text_reg.storage[0x607] = std::byte{0xC3};

    // .rdata at +0x3000 (Read)
    auto& rdata_reg =
        backend->map_region(Address{kModBase + 0x3000}, 0x2000, MemoryProtection::Read);

    // Static CPython core fingerprint strings (no python27.dll imported!)
    write_cstr(rdata_reg.storage, 0x000, "builtin_function_or_method");
    write_cstr(rdata_reg.storage, 0x020, "2.7.18 (default, static)");
    write_cstr(rdata_reg.storage, 0x03C, "member_descriptor");
    write_cstr(rdata_reg.storage, 0x050, "net");
    write_cstr(rdata_reg.storage, 0x060, "chr");
    write_cstr(rdata_reg.storage, 0x070, "SendChatPacket");
    write_cstr(rdata_reg.storage, 0x090, "GetServerInfo");
    write_cstr(rdata_reg.storage, 0x0B0, "SetPosition");
    write_cstr(rdata_reg.storage, 0x0D0, "health");
    write_cstr(rdata_reg.storage, 0x0E0, "move_speed");
    write_cstr(rdata_reg.storage, 0x0F0, "character_name");

    // 1. Embedded _inittab at RVA 0x3100 (offset 0x100 in .rdata):
    //    { "net", initnet (0x140001600) }, { 0, 0 }
    write_u64(rdata_reg.storage, 0x100 + 0, kModBase + 0x3050); // "net"
    write_u64(rdata_reg.storage, 0x100 + 8, kModBase + 0x1600); // initnet
    write_u64(rdata_reg.storage, 0x100 + 16, 0);
    write_u64(rdata_reg.storage, 0x100 + 24, 0);

    // 2. PyMethodDef table for "net" at RVA 0x3200 (offset 0x200 in .rdata):
    //    Entry 0: {"SendChatPacket", 0x140001100, METH_VARARGS (1), 0}
    write_u64(rdata_reg.storage, 0x200 + 0, kModBase + 0x3070);
    write_u64(rdata_reg.storage, 0x200 + 8, kModBase + 0x1100);
    write_u32(rdata_reg.storage, 0x200 + 16, 0x0001u);
    write_u32(rdata_reg.storage, 0x200 + 20, 0u);
    write_u64(rdata_reg.storage, 0x200 + 24, 0);
    //    Entry 1: {"GetServerInfo", 0x140001140, METH_NOARGS (4), 0}
    write_u64(rdata_reg.storage, 0x220 + 0, kModBase + 0x3090);
    write_u64(rdata_reg.storage, 0x220 + 8, kModBase + 0x1140);
    write_u32(rdata_reg.storage, 0x220 + 16, 0x0004u);
    write_u32(rdata_reg.storage, 0x220 + 20, 0u);
    write_u64(rdata_reg.storage, 0x220 + 24, 0);
    //    Sentinel {0, 0, 0, 0} at 0x240

    // 3. PyMethodDef table for "chr" at RVA 0x3300 (offset 0x300 in .rdata):
    //    Entry 0: {"SetPosition", 0x140001180, METH_VARARGS (1), 0}
    write_u64(rdata_reg.storage, 0x300 + 0, kModBase + 0x30B0);
    write_u64(rdata_reg.storage, 0x300 + 8, kModBase + 0x1180);
    write_u32(rdata_reg.storage, 0x300 + 16, 0x0001u);
    write_u32(rdata_reg.storage, 0x300 + 20, 0u);
    write_u64(rdata_reg.storage, 0x300 + 24, 0);
    //    Sentinel {0, 0, 0, 0} at 0x320

    // 4. PyMemberDef table at RVA 0x3400 (offset 0x400 in .rdata, 40 bytes per entry on x64):
    //    Entry 0: {"health", T_INT (1), offset 0x24, flags 0, doc 0}
    write_u64(rdata_reg.storage, 0x400 + 0, kModBase + 0x30D0);
    write_i32(rdata_reg.storage, 0x400 + 8, 1); // T_INT
    write_i32(rdata_reg.storage, 0x400 + 12, 0);
    write_u64(rdata_reg.storage, 0x400 + 16, 0x24); // non-virtual struct offset 0x24!
    write_i32(rdata_reg.storage, 0x400 + 24, 0);
    write_i32(rdata_reg.storage, 0x400 + 28, 0);
    write_u64(rdata_reg.storage, 0x400 + 32, 0);
    //    Entry 1: {"move_speed", T_FLOAT (3), offset 0x28, flags 0, doc 0}
    write_u64(rdata_reg.storage, 0x428 + 0, kModBase + 0x30E0);
    write_i32(rdata_reg.storage, 0x428 + 8, 3); // T_FLOAT
    write_i32(rdata_reg.storage, 0x428 + 12, 0);
    write_u64(rdata_reg.storage, 0x428 + 16, 0x28); // non-virtual struct offset 0x28!

    // 5. PyGetSetDef table at RVA 0x3500 (offset 0x500 in .rdata, 40 bytes per entry on x64):
    //    Entry 0: {"character_name", getter 0x1400011C0, setter 0x140001200, doc 0, closure 0}
    write_u64(rdata_reg.storage, 0x500 + 0, kModBase + 0x30F0);
    write_u64(rdata_reg.storage, 0x500 + 8, kModBase + 0x11C0);
    write_u64(rdata_reg.storage, 0x500 + 16, kModBase + 0x1200);
    write_u64(rdata_reg.storage, 0x500 + 24, 0);
    write_u64(rdata_reg.storage, 0x500 + 32, 0);

    Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange mod_range{Address{kModBase}, 0x5000};

    auto py_cat = PythonBridgeScanner::discover_all(proc, mod_range);
    REQUIRE(py_cat.has_value());

    // Verify static embedded Python detection without any python.dll!
    REQUIRE(py_cat->environment.deployment == PythonDeployment::StaticEmbedded);
    REQUIRE(py_cat->environment.framework == PythonFramework::CPythonCAPI);
    REQUIRE(py_cat->environment.version_hint == "2.7");
    REQUIRE(py_cat->environment.static_init_module_address == Address{kModBase + 0x1800});

    // Verify _inittab discovery
    REQUIRE(py_cat->inittab_entries.size() == 1);
    REQUIRE(py_cat->inittab_entries[0].module_name == "net");
    REQUIRE(py_cat->inittab_entries[0].init_function_address == Address{kModBase + 0x1600});

    // Verify PyMethodDef tables & xref-based module naming ("net" via _inittab, "chr" via LEA xref!)
    REQUIRE(py_cat->method_tables.size() == 2);
    auto send_chat = py_cat->find_method("net.SendChatPacket");
    REQUIRE(send_chat.has_value());
    REQUIRE(send_chat->cpp_function_address == Address{kModBase + 0x1100});

    auto set_pos = py_cat->find_method("chr.SetPosition");
    REQUIRE(set_pos.has_value());
    REQUIRE(set_pos->cpp_function_address == Address{kModBase + 0x1180});

    // Verify PyMemberDef non-virtual struct field offsets
    REQUIRE(py_cat->member_entries.size() == 2);
    REQUIRE(py_cat->member_entries[0].name == "health");
    REQUIRE(py_cat->member_entries[0].offset == 0x24);
    REQUIRE(py_cat->member_entries[1].name == "move_speed");
    REQUIRE(py_cat->member_entries[1].offset == 0x28);

    // Verify PyGetSetDef getter/setter discovery
    REQUIRE(py_cat->getset_entries.size() == 1);
    REQUIRE(py_cat->getset_entries[0].name == "character_name");
    REQUIRE(py_cat->getset_entries[0].getter_address == Address{kModBase + 0x11C0});
    REQUIRE(py_cat->getset_entries[0].setter_address == Address{kModBase + 0x1200});

    // Export to TypeRegistry
    reflection::TypeRegistry reg{};
    REQUIRE(py_cat->export_to_registry(reg).has_value());
    auto net_mod = reg.find_by_name("python::net");
    REQUIRE(net_mod.has_value());
    REQUIRE(net_mod->find_method("SendChatPacket") != nullptr);

    // Verify TargetProfile ResolutionStrategy::PythonMethod end-to-end
    targets::TargetProfile tp{};
    tp.application.application_id = "com.game.staticpy";
    tp.application.executables = {"GameClient.exe"};
    targets::TargetBuild b{};
    b.build_id = "v1";
    b.architecture = targets::TargetArch::X64;
    b.modules.push_back(targets::ModuleFingerprint{
        .module_id = "main",
        .file_name = "GameClient.exe",
        .architecture = targets::TargetArch::X64,
        .size_of_image = 0x5000,
        .sha256 = "deadbeef",
    });
    targets::AddressEntry ae{};
    ae.id = "fn.send_chat";
    ae.name = "SendChatPacket";
    ae.kind = targets::AddressKind::Function;
    ae.module_id = "main";
    ae.primary = targets::ResolutionRecipe{
        .strategy = targets::ResolutionStrategy::PythonMethod,
        .python_method = "net.SendChatPacket",
    };
    ae.validation = targets::default_validation_policy_for(targets::AddressKind::Function);
    b.addresses.push_back(ae);
    tp.builds.push_back(b);

    // Test JSON roundtrip of PythonMethod strategy
    auto jv = targets::serialize_target_profile_to_json(tp);
    REQUIRE(jv.has_value());
    auto tp_back = targets::deserialize_target_profile_from_json(*jv);
    REQUIRE(tp_back.has_value());
    REQUIRE(tp_back->builds[0].addresses[0].primary.strategy ==
            targets::ResolutionStrategy::PythonMethod);
    REQUIRE(tp_back->builds[0].addresses[0].primary.python_method == "net.SendChatPacket");

    targets::TargetModuleContext mod_ctx{};
    mod_ctx.module_id = "main";
    mod_ctx.range = mod_range;
    mod_ctx.fingerprint = b.modules[0];

    targets::AddressResolver resolver{proc, {mod_ctx}};
    auto outcome = resolver.resolve_entry(*tp_back, "fn.send_chat", targets::PersistPolicy::ReadOnly);
    REQUIRE(outcome.verified().has_value());
    REQUIRE(outcome.verified()->address() == Address{kModBase + 0x1100});
}

TEST_CASE("PythonBridgeScanner accepts immortal type objects and avoids weak framework fingerprints",
          "[rtti][python]") {
    using namespace tessera;
    using namespace tessera::rtti;

    // CPython 3.13 64-bit GIL build uses UINT_MAX (0xFFFFFFFF) for immortal objects.
    constexpr std::uint64_t kModBase = 0x150000000ULL;
    auto type_backend = std::make_shared<testing::FakeMemoryBackend>();
    auto& type_region =
        type_backend->map_region(Address{kModBase}, 0x2000, MemoryProtection::Read);
    write_u64(type_region.storage, 0x100, 0xFFFFFFFFULL); // ob_refcnt
    write_u64(type_region.storage, 0x108, 0);              // ob_type placeholder
    write_u64(type_region.storage, 0x110, 0);              // ob_size
    write_u64(type_region.storage, 0x118, kModBase + 0x800); // tp_name
    write_u64(type_region.storage, 0x120, 20);              // tp_basicsize
    write_u64(type_region.storage, 0x128, 0);               // tp_itemsize
    write_u64(type_region.storage, 0x100 + 29 * 8, kModBase + 0x900); // tp_methods
    write_u64(type_region.storage, 0x100 + 30 * 8, kModBase + 0xA00); // tp_members
    write_u64(type_region.storage, 0x100 + 31 * 8, kModBase + 0xB00); // tp_getset
    write_cstr(type_region.storage, 0x800, "demo.Probe");

    Process type_proc = testing::FakeMemoryBackend::make_process(type_backend, Architecture::X64);
    auto types = PythonBridgeScanner::scan_type_objects(type_proc, AddressRange{Address{kModBase}, 0x2000});
    REQUIRE(types.has_value());
    REQUIRE(std::any_of(types->begin(), types->end(), [](const auto& type) {
        return type.type_name == "demo.Probe" && type.basic_size == 20 &&
               type.methods_table_address == Address{kModBase + 0x900} &&
               type.members_table_address == Address{kModBase + 0xA00} &&
               type.getset_table_address == Address{kModBase + 0xB00};
    }));

    const auto detect = [](std::initializer_list<std::string_view> strings) {
        constexpr std::uint64_t base = 0x160000000ULL;
        auto backend = std::make_shared<testing::FakeMemoryBackend>();
        auto& region = backend->map_region(Address{base}, 0x2000, MemoryProtection::Read);
        std::size_t off = 0x100;
        for (const auto value : strings) {
            write_cstr(region.storage, off, value);
            off += value.size() + 1;
            off = (off + 7) & ~std::size_t{7};
        }
        Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
        return PythonBridgeScanner::detect_environment(proc, AddressRange{Address{base}, 0x2000});
    };

    auto weak_pybind = detect({"pybind11"});
    REQUIRE(weak_pybind.has_value());
    REQUIRE(weak_pybind->framework == PythonFramework::Unknown);
    REQUIRE(weak_pybind->deployment == PythonDeployment::None);

    auto strong_pybind = detect({"pybind11", "pybind11::detail"});
    REQUIRE(strong_pybind.has_value());
    REQUIRE(strong_pybind->framework == PythonFramework::PyBind11);

    auto weak_boost = detect({"boost::python"});
    REQUIRE(weak_boost.has_value());
    REQUIRE(weak_boost->framework == PythonFramework::Unknown);

    auto strong_boost = detect({"boost::python", "boost::python::objects"});
    REQUIRE(strong_boost.has_value());
    REQUIRE(strong_boost->framework == PythonFramework::BoostPython);

    auto weak_cython = detect({"__pyx_module_name"});
    REQUIRE(weak_cython.has_value());
    REQUIRE(weak_cython->framework == PythonFramework::Unknown);

    auto strong_cython = detect({"__pyx_module_name", "cython_function_or_method"});
    REQUIRE(strong_cython.has_value());
    REQUIRE(strong_cython->framework == PythonFramework::Cython);

    auto duplicate_core_marker =
        detect({"builtin_function_or_method", "builtin_function_or_method"});
    REQUIRE(duplicate_core_marker.has_value());
    REQUIRE(duplicate_core_marker->framework == PythonFramework::CPythonCAPI);
    REQUIRE(duplicate_core_marker->deployment == PythonDeployment::None);

    auto static_python = detect({"builtin_function_or_method", "member_descriptor",
                                 "2.7.18 (default, static)"});
    REQUIRE(static_python.has_value());
    REQUIRE(static_python->framework == PythonFramework::CPythonCAPI);
    REQUIRE(static_python->deployment == PythonDeployment::StaticEmbedded);
    REQUIRE(static_python->version_hint == "2.7");
    REQUIRE(static_python->is_present());
}


TEST_CASE("PythonBridgeScanner bounds type metadata and tolerates partial reads",
          "[rtti][python-bridge][bounds][partial-read]") {
    using namespace tessera;
    using namespace tessera::rtti;

    // The bridge scans bounded fixed-layout C-API metadata; it does not recursively
    // traverse PyObject dict/list graphs, so object-graph cycle/depth tests are not applicable.

    const auto scan_type = [](std::uint64_t base,
                              std::uint64_t name_pointer,
                              std::uint64_t basic_size,
                              std::uint64_t item_size,
                              std::uint64_t methods_pointer,
                              std::optional<std::size_t> readable_prefix,
                              std::string_view name) {
        auto backend = std::make_shared<testing::FakeMemoryBackend>();
        auto& region = backend->map_region(
            Address{base}, 0x2000, MemoryProtection::Read);
        if (readable_prefix.has_value()) {
            region.readable_prefix_limit = *readable_prefix;
        }

        constexpr std::size_t type_offset = 0x100;
        write_u64(region.storage, type_offset + 0, 1);       // ob_refcnt
        write_u64(region.storage, type_offset + 8, 0);       // ob_type
        write_u64(region.storage, type_offset + 16, 0);      // ob_size
        write_u64(region.storage, type_offset + 24, name_pointer);
        write_u64(region.storage, type_offset + 32, basic_size);
        write_u64(region.storage, type_offset + 40, item_size);
        write_u64(region.storage, type_offset + 29 * 8, methods_pointer);
        write_u64(region.storage, type_offset + 30 * 8, 0);
        write_u64(region.storage, type_offset + 31 * 8, 0);

        if (name_pointer >= base && name_pointer - base < region.storage.size()) {
            const auto offset = static_cast<std::size_t>(name_pointer - base);
            if (offset + name.size() + 1 <= region.storage.size()) {
                write_cstr(region.storage, offset, name);
            }
        }

        Process process = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
        return PythonBridgeScanner::scan_type_objects(
            process, AddressRange{Address{base}, 0x2000});
    };

    constexpr std::uint64_t base = 0x1A0000000ULL;
    auto invalid_name = scan_type(base, base + 0x4000, 24, 0, 0, std::nullopt, "demo.InvalidName");
    REQUIRE(invalid_name.has_value());
    REQUIRE(invalid_name->empty());

    auto oversized_basic = scan_type(base + 0x10000, base + 0x10800, 0x10001, 0, 0,
                                     std::nullopt, "demo.OversizedBasic");
    REQUIRE(oversized_basic.has_value());
    REQUIRE(oversized_basic->empty());

    auto oversized_item = scan_type(base + 0x20000, base + 0x20800, 24, 0x1001, 0,
                                    std::nullopt, "demo.OversizedItem");
    REQUIRE(oversized_item.has_value());
    REQUIRE(oversized_item->empty());

    const std::string long_name(97, 'A');
    auto oversized_name = scan_type(base + 0x30000, base + 0x30800, 24, 0, 0,
                                    std::nullopt, long_name);
    REQUIRE(oversized_name.has_value());
    REQUIRE(oversized_name->empty());

    auto invalid_methods = scan_type(base + 0x40000, base + 0x40800, 24, 0,
                                     base + 0x44000, std::nullopt, "demo.InvalidMethods");
    REQUIRE(invalid_methods.has_value());
    REQUIRE(invalid_methods->size() == 1);
    REQUIRE(invalid_methods->front().type_name == "demo.InvalidMethods");
    REQUIRE(invalid_methods->front().methods_table_address.is_null());

    auto partial = scan_type(base + 0x50000, base + 0x50800, 24, 0, 0,
                             std::size_t{0x180}, "demo.PartialRead");
    REQUIRE(partial.has_value());
    REQUIRE(partial->empty());
}

