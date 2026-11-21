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

TEST_CASE("RTTI discovery rejects a vftable whose first virtual target escapes the module",
          "[rtti][malformed][vftable]") {
    using namespace tessera;
    using namespace tessera::rtti;

    constexpr std::uint64_t base = 0x150000000ULL;
    auto backend = std::make_shared<testing::FakeMemoryBackend>();
    auto& image = backend->map_region(
        Address{base}, 0x5000, MemoryProtection::ReadWrite | MemoryProtection::Execute);

    // TypeDescriptor and its mangled name.
    write_cstr(image.storage, 0x2100 + 16, ".?AVBrokenVftable@Game@@");

    // A structurally valid x64 CompleteObjectLocator and ClassHierarchyDescriptor.
    write_u32(image.storage, 0x23C0 + 0, 0);
    write_u32(image.storage, 0x23C0 + 4, 0);
    write_u32(image.storage, 0x23C0 + 8, 0);
    write_u32(image.storage, 0x23C0 + 12, 0);
    write_u32(image.storage, 0x2400 + 0, 1);
    write_u32(image.storage, 0x2400 + 4, 0);
    write_u32(image.storage, 0x2400 + 8, 0);
    write_u32(image.storage, 0x2400 + 12, 0x2100);
    write_u32(image.storage, 0x2400 + 16, 0x23C0);
    write_u32(image.storage, 0x2400 + 20, 0x2400);

    // The meta-slot resolves to the valid COL, but the first virtual function
    // pointer deliberately escapes the module and must not yield a class.
    write_u64(image.storage, 0x2500, base + 0x2400);
    write_u64(image.storage, 0x2508, 0xDEAD0000ULL);

    Process process = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, 0x5000});
    REQUIRE(catalog.has_value());
    REQUIRE(catalog->classes().empty());
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
