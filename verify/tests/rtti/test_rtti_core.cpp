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
