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

TEST_CASE("ObjectView validates reflected field and bitfield bounds", "[rtti][object-view][safety]") {
    using namespace tessera;
    using namespace tessera::testing;
    using namespace tessera::reflection;
    using namespace tessera::rtti;

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
        .name = "narrow",
        .offset = 0,
        .size = 1,
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

    auto too_wide = view.read_field<std::uint16_t>("narrow");
    REQUIRE_FALSE(too_wide.has_value());
    REQUIRE(too_wide.error().code == ErrorCode::InvalidArgument);

    auto bitfield = view.read_bitfield("invalid_bits");
    REQUIRE_FALSE(bitfield.has_value());
    REQUIRE(bitfield.error().code == ErrorCode::InvalidArgument);
}

TEST_CASE("ObjectView owns its Process and resolves virtual bases without adding vbptr offset",
          "[rtti][object-view][safety]") {
    using namespace tessera;
    using namespace tessera::testing;
    using namespace tessera::reflection;
    using namespace tessera::rtti;

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
