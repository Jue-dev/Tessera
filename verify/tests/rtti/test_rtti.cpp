#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/rtti/object_view.hpp"
#include "tessera/rtti/python_bridge.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/targets/target_profile_json.hpp"
#include "tessera/targets/target_runtime.hpp"

namespace {

using namespace tessera;

void write_u32(std::vector<std::byte>& buf, std::size_t off, std::uint32_t val) {
    std::memcpy(buf.data() + off, &val, 4);
}

void write_i32(std::vector<std::byte>& buf, std::size_t off, std::int32_t val) {
    std::memcpy(buf.data() + off, &val, 4);
}

void write_u64(std::vector<std::byte>& buf, std::size_t off, std::uint64_t val) {
    std::memcpy(buf.data() + off, &val, 8);
}

void write_f32(std::vector<std::byte>& buf, std::size_t off, float val) {
    std::memcpy(buf.data() + off, &val, 4);
}

void write_cstr(std::vector<std::byte>& buf, std::size_t off, std::string_view s) {
    std::memcpy(buf.data() + off, s.data(), s.size());
    buf[off + s.size()] = std::byte{0};
}

} // namespace


TEST_CASE("RTTI distinguishes virtual bases from the CHD virtual-branching bit", "[rtti]") {
    using namespace tessera::rtti;

    RttiClassDescriptor simple_virtual{};
    RttiBaseEntry virtual_base{};
    virtual_base.pmd = MsvcPmd{.mdisp = 0, .pdisp = 0, .vdisp = 4};
    simple_virtual.base_classes.push_back(virtual_base);

    REQUIRE(simple_virtual.has_virtual_base_classes());
    REQUIRE(simple_virtual.is_virtual_inheritance());
    REQUIRE_FALSE(simple_virtual.has_virtual_branching_hierarchy());

    RttiClassDescriptor branching_virtual{};
    branching_virtual.chd_attributes = 0x02u;

    REQUIRE_FALSE(branching_virtual.has_virtual_base_classes());
    REQUIRE(branching_virtual.has_virtual_branching_hierarchy());
    REQUIRE(branching_virtual.is_virtual_inheritance());
}

TEST_CASE("MSVC RTTI symbol demangling and non-virtual reflection / ObjectView", "[rtti][reflection]") {
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::reflection;

    REQUIRE(demangle_msvc_symbol(".?AVPlayer@Game@Engine@@") == "Engine::Game::Player");
    REQUIRE(demangle_msvc_symbol(".?AUVec3@Math@@") == "Math::Vec3");
    REQUIRE(demangle_msvc_symbol(".?AW4AIState@AI@@") == "AI::AIState");
    REQUIRE(demangle_msvc_symbol(".?AV?$Vector@M@Math@@") == "Math::Vector<float>");

    enum class WeaponState : std::int32_t {
        Idle = 0,
        Firing = 1,
        Reloading = 2,
    };

    auto enum_type = EnumBuilder<WeaponState>("Game::WeaponState")
                         .value("Idle", WeaponState::Idle)
                         .value("Firing", WeaponState::Firing)
                         .value("Reloading", WeaponState::Reloading)
                         .build();
    REQUIRE(enum_type.kind == TypeKind::Enum);
    REQUIRE(enum_type.enum_info.has_value());
    REQUIRE(enum_type.enum_info->find_by_name("Reloading")->value == 2);
    REQUIRE(enum_type.enum_info->find_by_value(1)->name == "Firing");

    struct NonVirtualTransform {
        float x;
        float y;
        std::uint32_t flags;
    };

    auto transform_type =
        TypeBuilder<NonVirtualTransform>("Math::NonVirtualTransform")
            .field("x", TypeId::from_name("float"), 0, 4)
            .field("y", TypeId::from_name("float"), 4, 4)
            .bitfield("is_active", TypeId::from_name("uint32"), 8, 4, 0, 1)
            .bitfield("layer_id", TypeId::from_name("uint32"), 8, 4, 4, 4)
            .non_virtual_method("UpdateTransform", Rva{0x1200})
            .build();

    auto backend = std::make_shared<testing::FakeMemoryBackend>();
    auto& data_reg = backend->map_region(Address{0x200000}, 0x1000, MemoryProtection::ReadWrite);
    write_f32(data_reg.storage, 0x100 + 0, 42.5f);
    write_f32(data_reg.storage, 0x100 + 4, -18.25f);
    write_u32(data_reg.storage, 0x100 + 8, (1u << 0) | (7u << 4));

    Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    ObjectView view{proc, Address{0x200100}, transform_type};

    REQUIRE(*view.read_field<float>("x") == 42.5f);
    REQUIRE(*view.read_field<float>("y") == -18.25f);
    REQUIRE(*view.read_bitfield("is_active") == 1ULL);
    REQUIRE(*view.read_bitfield("layer_id") == 7ULL);

    REQUIRE(view.write_field<float>("x", 99.0f).has_value());
    REQUIRE(*view.read_field<float>("x") == 99.0f);
    REQUIRE(*view.resolve_method("UpdateTransform", Address{0x140000000ULL}) ==
            Address{0x140001200ULL});
}

TEST_CASE("RttiCatalog discovers polymorphic classes, inheritance, instances, and dynamic_cast",
          "[rtti]") {
    using namespace tessera;
    using namespace tessera::rtti;

    constexpr std::uint64_t kModBase = 0x140000000ULL;
    auto backend = std::make_shared<testing::FakeMemoryBackend>();

    // .text at +0x1000 (Executable)
    auto& text_reg =
        backend->map_region(Address{kModBase + 0x1000}, 0x1000, MemoryProtection::ExecuteRead);
    text_reg.storage[0x100] = std::byte{0xC3}; // Entity::vfunc0 at RVA 0x1100
    text_reg.storage[0x200] = std::byte{0xC3}; // Player::vfunc0 at RVA 0x1200
    text_reg.storage[0x240] = std::byte{0xC3}; // Player::vfunc1 at RVA 0x1240

    // .rdata at +0x2000 (Read)
    auto& rdata_reg =
        backend->map_region(Address{kModBase + 0x2000}, 0x2000, MemoryProtection::Read);

    // 1. TypeDescriptor for Game::Entity at RVA 0x2100 (offset 0x100 in rdata)
    write_cstr(rdata_reg.storage, 0x100 + 16, ".?AVEntity@Game@@");

    // 2. TypeDescriptor for Game::Player at RVA 0x2180 (offset 0x180 in rdata)
    write_cstr(rdata_reg.storage, 0x180 + 16, ".?AVPlayer@Game@@");

    // 3. Non-virtual struct TypeDescriptor .?AUVector3@Math@@ at RVA 0x2200 (no COL/vtable!)
    write_cstr(rdata_reg.storage, 0x200 + 16, ".?AUVector3@Math@@");

    // 4. BaseClassDescriptor for Player (self) at RVA 0x2300 (offset 0x300)
    write_u32(rdata_reg.storage, 0x300 + 0, 0x2180); // pTypeDescriptor (Player)
    write_u32(rdata_reg.storage, 0x300 + 4, 1);      // numContainedBases
    write_i32(rdata_reg.storage, 0x300 + 8, 0);      // mdisp = 0
    write_i32(rdata_reg.storage, 0x300 + 12, -1);    // pdisp = -1
    write_i32(rdata_reg.storage, 0x300 + 16, 0);     // vdisp = 0

    // 5. BaseClassDescriptor for Entity (base of Player at mdisp = 16) at RVA 0x2340 (offset 0x340)
    write_u32(rdata_reg.storage, 0x340 + 0, 0x2100); // pTypeDescriptor (Entity)
    write_u32(rdata_reg.storage, 0x340 + 4, 0);      // numContainedBases
    write_i32(rdata_reg.storage, 0x340 + 8, 16);     // mdisp = 16
    write_i32(rdata_reg.storage, 0x340 + 12, -1);    // pdisp = -1
    write_i32(rdata_reg.storage, 0x340 + 16, 0);     // vdisp = 0

    // 6. BaseClassArray for Player at RVA 0x2380 (offset 0x380)
    write_u32(rdata_reg.storage, 0x380 + 0, 0x2300);
    write_u32(rdata_reg.storage, 0x380 + 4, 0x2340);

    // 7. ClassHierarchyDescriptor for Player at RVA 0x23C0 (offset 0x3C0)
    write_u32(rdata_reg.storage, 0x3C0 + 0, 0);      // signature
    write_u32(rdata_reg.storage, 0x3C0 + 4, 0);      // attributes
    write_u32(rdata_reg.storage, 0x3C0 + 8, 2);      // numBaseClasses = 2
    write_u32(rdata_reg.storage, 0x3C0 + 12, 0x2380); // pBaseClassArray

    // 8. CompleteObjectLocator for Player at RVA 0x2400 (offset 0x400)
    write_u32(rdata_reg.storage, 0x400 + 0, 1);      // signature = 1 (x64)
    write_u32(rdata_reg.storage, 0x400 + 4, 0);      // offset = 0
    write_u32(rdata_reg.storage, 0x400 + 8, 0);      // cdOffset = 0
    write_u32(rdata_reg.storage, 0x400 + 12, 0x2180); // pTypeDescriptor (Player)
    write_u32(rdata_reg.storage, 0x400 + 16, 0x23C0); // pClassDescriptor (CHD)
    write_u32(rdata_reg.storage, 0x400 + 20, 0x2400); // pSelf = RVA 0x2400

    // 9. Player vftable meta-pointer at RVA 0x2500, vftable at RVA 0x2508
    write_u64(rdata_reg.storage, 0x500, kModBase + 0x2400); // vftable[-1] -> COL
    write_u64(rdata_reg.storage, 0x508, kModBase + 0x1200); // vftable[0] -> Player::vfunc0
    write_u64(rdata_reg.storage, 0x510, kModBase + 0x1240); // vftable[1] -> Player::vfunc1

    // .data at +0x4000 with a live Player instance at RVA 0x4100
    auto& data_reg =
        backend->map_region(Address{kModBase + 0x4000}, 0x1000, MemoryProtection::ReadWrite);
    write_u64(data_reg.storage, 0x100, kModBase + 0x2508); // vptr -> Player vftable
    write_i32(data_reg.storage, 0x108, 100);               // hp = 100
    write_f32(data_reg.storage, 0x10C, 3.5f);              // speed = 3.5f

    Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange mod_range{Address{kModBase}, 0x5000};

    auto cat_res = RttiCatalog::discover_all(proc, mod_range);
    REQUIRE(cat_res.has_value());
    REQUIRE(cat_res->classes().size() == 1);

    auto player_cls = cat_res->find_class("Game::Player");
    REQUIRE(player_cls.has_value());
    REQUIRE(player_cls->vftable_address == Address{kModBase + 0x2508});
    REQUIRE(player_cls->virtual_methods.size() == 2);
    REQUIRE(player_cls->virtual_methods[0] == Address{kModBase + 0x1200});
    REQUIRE(player_cls->base_classes.size() == 1);
    REQUIRE(player_cls->base_classes[0].demangled_name == "Game::Entity");
    REQUIRE(player_cls->base_classes[0].pmd.mdisp == 16);

    // Identify live instance and cast to base Game::Entity
    const Address player_inst{kModBase + 0x4100};
    auto id_inst = cat_res->identify_instance(proc, player_inst);
    REQUIRE(id_inst.has_value());
    REQUIRE(id_inst->demangled_name == "Game::Player");

    auto entity_subobj = cat_res->cast_to(proc, player_inst, "Game::Entity");
    REQUIRE(entity_subobj.has_value());
    REQUIRE(*entity_subobj == Address{kModBase + 0x4110});

    // Blind Discovery: scan_all_type_descriptors finds both polymorphic Player/Entity AND non-virtual Math::Vector3
    auto all_tds = BinaryExplorer::scan_all_type_descriptors(proc, mod_range, &(*cat_res));
    REQUIRE(all_tds.has_value());
    REQUIRE(all_tds->size() == 3);
    bool found_non_virtual_vec3 = false;
    for (const auto& td : *all_tds) {
        if (td.demangled_name == "Math::Vector3") {
            REQUIRE(td.kind == DiscoveredTypeKind::Struct);
            REQUIRE_FALSE(td.has_vtable);
            found_non_virtual_vec3 = true;
        }
    }
    REQUIRE(found_non_virtual_vec3);

    // Find live instances in .data
    auto instances = BinaryExplorer::find_instances(
        proc, AddressRange{Address{kModBase + 0x4000}, 0x1000}, *cat_res);
    REQUIRE(instances.has_value());
    REQUIRE(instances->size() == 1);
    REQUIRE(instances->front().instance_address == player_inst);

    // Dissect memory of live instance
    auto dissected = BinaryExplorer::dissect_memory(proc, mod_range, player_inst, 16, &(*cat_res));
    REQUIRE(dissected.has_value());
    REQUIRE(dissected->size() == 3);
    REQUIRE((*dissected)[0].kind == MemorySlotKind::VTableInstance);
    REQUIRE((*dissected)[0].resolved_class_name == "Game::Player");
    REQUIRE((*dissected)[1].kind == MemorySlotKind::Integer32);
    REQUIRE((*dissected)[1].i32_value == 100);
    REQUIRE((*dissected)[2].kind == MemorySlotKind::Float32);
    REQUIRE((*dissected)[2].f32_value == 3.5f);
}

TEST_CASE("BinaryExplorer reconstructs non-virtual struct layout from function instructions",
          "[rtti][discovery]") {
    using namespace tessera;
    using namespace tessera::rtti;

    auto backend = std::make_shared<testing::FakeMemoryBackend>();
    auto& text_reg =
        backend->map_region(Address{0x140001000ULL}, 0x1000, MemoryProtection::ExecuteRead);

    // Machine code accessing non-virtual struct via RCX (`this`):
    // 8B 41 10          mov eax, [rcx + 0x10]         (read Int32 at +0x10)
    // 89 51 14          mov [rcx + 0x14], edx         (write Int32 at +0x14)
    // F3 0F 10 41 18    movss xmm0, [rcx + 0x18]      (read Float32 at +0x18)
    // C6 41 20 01       mov byte ptr [rcx + 0x20], 1  (write UInt8 at +0x20)
    // 48 8B 41 28       mov rax, [rcx + 0x28]         (read UInt64OrPointer at +0x28)
    // C3                ret
    const std::array<std::uint8_t, 20> code_bytes{
        0x8B, 0x41, 0x10,
        0x89, 0x51, 0x14,
        0xF3, 0x0F, 0x10, 0x41, 0x18,
        0xC6, 0x41, 0x20, 0x01,
        0x48, 0x8B, 0x41, 0x28,
        0xC3,
    };
    std::memcpy(text_reg.storage.data(), code_bytes.data(), code_bytes.size());

    Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    auto recon = BinaryExplorer::reconstruct_struct(
        proc, AddressRange{Address{0x140001000ULL}, code_bytes.size()}, "Game::ActorData");
    REQUIRE(recon.has_value());
    REQUIRE(recon->fields.size() == 5);
    REQUIRE(recon->estimated_size == 0x30);

    REQUIRE(recon->fields[0].offset == 0x10);
    REQUIRE(recon->fields[0].kind == InferredFieldKind::Int32);
    REQUIRE(recon->fields[0].is_read);

    REQUIRE(recon->fields[1].offset == 0x14);
    REQUIRE(recon->fields[1].kind == InferredFieldKind::Int32);
    REQUIRE(recon->fields[1].is_written);

    REQUIRE(recon->fields[2].offset == 0x18);
    REQUIRE(recon->fields[2].kind == InferredFieldKind::Float32);

    REQUIRE(recon->fields[3].offset == 0x20);
    REQUIRE(recon->fields[3].kind == InferredFieldKind::UInt8);

    REQUIRE(recon->fields[4].offset == 0x28);
    REQUIRE(recon->fields[4].kind == InferredFieldKind::UInt64OrPointer);

    auto ti = recon->to_type_info();
    REQUIRE(ti.name == "Game::ActorData");
    REQUIRE(ti.members.size() == 5);
}

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

TEST_CASE("x86 32-bit RTTI discovery, virtual base PMD vbtable cast, RttiVTable and StringXref TargetProfile strategies",
          "[rtti][x86][targets]") {
    using namespace tessera;
    using namespace tessera::rtti;

    constexpr std::uint32_t kModBase = 0x00400000u;
    auto backend = std::make_shared<testing::FakeMemoryBackend>();

    // .text at +0x1000 (Executable)
    auto& text_reg =
        backend->map_region(Address{kModBase + 0x1000}, 0x1000, MemoryProtection::ExecuteRead);
    text_reg.storage[0x100] = std::byte{0xC3}; // Boss::vfunc0 at VA 0x00401100
    text_reg.storage[0x200] = std::byte{0xE8}; // Caller at VA 0x00401200 calling 0x00401100
    write_i32(text_reg.storage, 0x201, 0x00401100 - (0x00401200 + 5));
    text_reg.storage[0x205] = std::byte{0x68}; // PUSH imm32 referencing string at VA 0x00402600
    write_u32(text_reg.storage, 0x206, kModBase + 0x2600);
    text_reg.storage[0x20A] = std::byte{0xC3};

    // .rdata at +0x2000 (Read)
    auto& rdata_reg =
        backend->map_region(Address{kModBase + 0x2000}, 0x1000, MemoryProtection::Read);

    // 32-bit TypeDescriptor: pVFTable (4), spare (4), name (+8)
    write_cstr(rdata_reg.storage, 0x100 + 8, ".?AVVirtualBase@Game@@");
    write_cstr(rdata_reg.storage, 0x180 + 8, ".?AVBoss@Game@@");

    // BaseClassDescriptor for Boss (self) at VA 0x00402300
    write_u32(rdata_reg.storage, 0x300 + 0, kModBase + 0x2180);
    write_u32(rdata_reg.storage, 0x300 + 4, 1);
    write_i32(rdata_reg.storage, 0x300 + 8, 0);
    write_i32(rdata_reg.storage, 0x300 + 12, -1);
    write_i32(rdata_reg.storage, 0x300 + 16, 0);

    // BaseClassDescriptor for VirtualBase (virtual inheritance: pdisp = 4, vdisp = 4, mdisp = 8) at VA 0x00402340
    write_u32(rdata_reg.storage, 0x340 + 0, kModBase + 0x2100);
    write_u32(rdata_reg.storage, 0x340 + 4, 0);
    write_i32(rdata_reg.storage, 0x340 + 8, 8);  // mdisp = 8
    write_i32(rdata_reg.storage, 0x340 + 12, 4); // pdisp = 4 (vbtable ptr at object + 4)
    write_i32(rdata_reg.storage, 0x340 + 16, 4); // vdisp = 4 (offset inside vbtable)

    // BaseClassArray at VA 0x00402380
    write_u32(rdata_reg.storage, 0x380 + 0, kModBase + 0x2300);
    write_u32(rdata_reg.storage, 0x380 + 4, kModBase + 0x2340);

    // ClassHierarchyDescriptor at VA 0x004023C0
    write_u32(rdata_reg.storage, 0x3C0 + 0, 0);
    write_u32(rdata_reg.storage, 0x3C0 + 4, 3); // MI + VI flags
    write_u32(rdata_reg.storage, 0x3C0 + 8, 2);
    write_u32(rdata_reg.storage, 0x3C0 + 12, kModBase + 0x2380);

    // 32-bit CompleteObjectLocator (signature == 0) at VA 0x00402400
    write_u32(rdata_reg.storage, 0x400 + 0, 0); // signature = 0 (x86)
    write_u32(rdata_reg.storage, 0x400 + 4, 0);
    write_u32(rdata_reg.storage, 0x400 + 8, 0);
    write_u32(rdata_reg.storage, 0x400 + 12, kModBase + 0x2180); // pTypeDescriptor (VA)
    write_u32(rdata_reg.storage, 0x400 + 16, kModBase + 0x23C0); // pClassDescriptor (VA)

    // 32-bit vftable[-1] at VA 0x00402500, vftable[0] at VA 0x00402504
    write_u32(rdata_reg.storage, 0x500, kModBase + 0x2400);
    write_u32(rdata_reg.storage, 0x504, kModBase + 0x1100);

    // vbtable at VA 0x00402580: entry at +4 holds displacement 0x20
    write_i32(rdata_reg.storage, 0x580 + 0, 0);
    write_i32(rdata_reg.storage, 0x580 + 4, 0x20);

    // String literal at VA 0x00402600 referenced by PUSH imm32 at VA 0x00401205
    write_cstr(rdata_reg.storage, 0x600, "BossSpawnedEvent");

    // Live Boss instance in .data at VA 0x00403100:
    //   +0x00: vptr -> 0x00402504
    //   +0x04: vbptr -> 0x00402580
    //   VirtualBase sub-object offset = pdisp(4) + vbtable[4](0x20) + mdisp(8) = +0x2C
    auto& data_reg =
        backend->map_region(Address{kModBase + 0x3000}, 0x1000, MemoryProtection::ReadWrite);
    write_u32(data_reg.storage, 0x100 + 0, kModBase + 0x2504);
    write_u32(data_reg.storage, 0x100 + 4, kModBase + 0x2580);

    Process proc_x86 = testing::FakeMemoryBackend::make_process(backend, Architecture::X86);
    const AddressRange mod_range{Address{kModBase}, 0x4000};

    auto cat = RttiCatalog::discover_all(proc_x86, mod_range);
    REQUIRE(cat.has_value());
    REQUIRE(cat->classes().size() == 1);
    REQUIRE(cat->classes()[0].demangled_name == "Game::Boss");

    const Address boss_inst{kModBase + 0x3100};
    auto vbase_addr = cat->cast_to(proc_x86, boss_inst, "Game::VirtualBase");
    REQUIRE(vbase_addr.has_value());
    REQUIRE(*vbase_addr == Address{kModBase + 0x312C});

    // Verify BinaryExplorer string scanning + xrefs + function discovery
    auto strs = BinaryExplorer::scan_strings(proc_x86, mod_range, 8, true);
    REQUIRE(strs.has_value());
    bool found_event_str = false;
    for (const auto& st : *strs) {
        if (st.value == "BossSpawnedEvent") {
            REQUIRE_FALSE(st.code_xrefs.empty());
            REQUIRE(st.code_xrefs.front() == Address{kModBase + 0x1205});
            found_event_str = true;
        }
    }
    REQUIRE(found_event_str);

    auto fns = BinaryExplorer::discover_functions(proc_x86, mod_range);
    REQUIRE(fns.has_value());
    REQUIRE_FALSE(fns->empty());

    // Verify TargetProfile ResolutionStrategy::RttiVTable and StringXref end-to-end
    targets::TargetProfile tp{};
    tp.application.application_id = "com.game.x86";
    tp.application.executables = {"GameX86.exe"};
    targets::TargetBuild b{};
    b.build_id = "x86-v1";
    b.architecture = targets::TargetArch::X86;
    b.modules.push_back(targets::ModuleFingerprint{
        .module_id = "main",
        .file_name = "GameX86.exe",
        .architecture = targets::TargetArch::X86,
        .size_of_image = 0x4000,
        .sha256 = "cafebabe",
    });

    b.addresses.push_back(targets::AddressEntry{
        .id = "boss.vfunc0",
        .name = "Boss::vfunc0",
        .kind = targets::AddressKind::Function,
        .module_id = "main",
        .primary =
            targets::ResolutionRecipe{
                .strategy = targets::ResolutionStrategy::RttiVTable,
                .class_name = "Game::Boss",
                .vtable_index = 0,
            },
        .validation = targets::default_validation_policy_for(targets::AddressKind::Function),
    });

    b.addresses.push_back(targets::AddressEntry{
        .id = "boss.spawn_xref",
        .name = "BossSpawnedEvent Xref",
        .kind = targets::AddressKind::Function,
        .module_id = "main",
        .primary =
            targets::ResolutionRecipe{
                .strategy = targets::ResolutionStrategy::StringXref,
                .string_literal = "BossSpawnedEvent",
            },
        .validation = targets::default_validation_policy_for(targets::AddressKind::Function),
    });
    tp.builds.push_back(b);

    auto json_str = targets::serialize_target_profile_to_json(tp);
    REQUIRE(json_str.has_value());
    auto tp_parsed = targets::deserialize_target_profile_from_json(*json_str);
    REQUIRE(tp_parsed.has_value());

    targets::TargetModuleContext mod_ctx{
        .module_id = "main",
        .file_name = "GameX86.exe",
        .range = mod_range,
        .fingerprint = b.modules[0],
    };
    targets::AddressResolver resolver{proc_x86, {mod_ctx}};

    auto res_vtable = resolver.resolve_entry(*tp_parsed, "boss.vfunc0");
    REQUIRE(res_vtable.verified().has_value());
    REQUIRE(res_vtable.verified()->address() == Address{kModBase + 0x1100});

    auto res_strxref = resolver.resolve_entry(*tp_parsed, "boss.spawn_xref");
    REQUIRE(res_strxref.verified().has_value());
    REQUIRE(res_strxref.verified()->address() == Address{kModBase + 0x1205});
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

TEST_CASE("ObjectView validates reflected field and bitfield bounds", "[rtti][object-view][safety]") {
    using namespace tessera;
    using namespace tessera::testing;
    using namespace tessera::reflection;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x900000}, 0x1000, MemoryProtection::ReadWrite);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);

    TypeInfo type{};
    type.name = "BoundsTest";
    type.size = 8;
    type.members.push_back(FieldInfo{
        .name = "out_of_bounds",
        .offset = 7,
        .size = 2,
    });
    type.members.push_back(FieldInfo{
        .name = "invalid_bits",
        .offset = 0,
        .size = 8,
        .bit_offset = 64,
        .bit_width = 1,
        .flags = FieldFlags::Bitfield,
    });
    ObjectView view{process, Address{0x900000}, type};

    auto field = view.read_field<std::uint16_t>("out_of_bounds");
    REQUIRE_FALSE(field.has_value());
    REQUIRE(field.error().code == ErrorCode::OutOfRange);

    auto bitfield = view.read_bitfield("invalid_bits");
    REQUIRE_FALSE(bitfield.has_value());
    REQUIRE(bitfield.error().code == ErrorCode::InvalidArgument);
}

TEST_CASE("ObjectView owns its Process and resolves virtual bases without adding vbptr offset",
          "[rtti][object-view][safety]") {
    using namespace tessera;
    using namespace tessera::testing;
    using namespace tessera::reflection;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0xA00000}, 0x2000, MemoryProtection::ReadWrite);
    backend->poke_value<std::uint64_t>(Address{0xA00004}, 0xA01000);
    backend->poke_value<std::int32_t>(Address{0xA01000}, 0x20);
    backend->poke_value<std::uint32_t>(Address{0xA00028}, 0x12345678u);

    std::optional<ObjectView> view;
    TypeInfo derived{};
    derived.name = "Derived";
    derived.size = 0x40;
    derived.bases.push_back(BaseClassInfo{
        .base_type = TypeId::from_name("Base"),
        .base_name = "Base",
        .offset = 0,
        .is_virtual = true,
        .mdisp = 8,
        .pdisp = 4,
        .vdisp = 0,
    });
    TypeInfo base{};
    base.name = "Base";
    base.id = TypeId::from_name("Base");
    base.size = 4;
    base.members.push_back(FieldInfo{.name = "value", .offset = 0, .size = 4});
    TypeRegistry registry{};
    REQUIRE(registry.register_type(base).has_value());

    {
        Process temporary = FakeMemoryBackend::make_process(backend, Architecture::X64);
        view.emplace(temporary, Address{0xA00000}, derived);
    }

    auto subobject = view->base_subobject(registry, "Base");
    REQUIRE(subobject.has_value());
    REQUIRE(subobject->address() == Address{0xA00028});
    REQUIRE(subobject->read_field<std::uint32_t>("value").value() == 0x12345678u);
}
