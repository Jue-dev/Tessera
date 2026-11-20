#include <catch2/catch_test_macros.hpp>

#include <string_view>

#include "tessera/reflection/reflection.hpp"

TEST_CASE("Reflection registry validates registrations and supports field lookups", "[reflection]") {
    using namespace tessera;

    reflection::TypeRegistry registry{};
    struct DummyVec3 {
        float x, y, z;
    };

    auto info = reflection::TypeBuilder<DummyVec3>("tessera::DummyVec3")
                    .member("x", reflection::TypeId::from_name("float"), 0, 4)
                    .member("y", reflection::TypeId::from_name("float"), 4, 4)
                    .member("z", reflection::TypeId::from_name("float"), 8, 4)
                    .method(reflection::MethodInfo{.name = "length"})
                    .base_raw(reflection::BaseClassInfo{
                        .base_type = reflection::TypeId::from_name("tessera::Base"),
                        .base_name = "tessera::Base",
                    })
                    .build();

    REQUIRE(info.find_member("x") != nullptr);
    REQUIRE(info.find_field("y") != nullptr);
    REQUIRE(info.find_field_at_offset(8) != nullptr);
    REQUIRE(info.find_method("length") != nullptr);
    REQUIRE(info.find_base(reflection::TypeId::from_name("tessera::Base")) != nullptr);
    REQUIRE(info.find_member("missing") == nullptr);
    REQUIRE(info.find_field("") == nullptr);
    REQUIRE(info.find_field_at_offset(3) == nullptr);
    REQUIRE(info.find_method("missing") == nullptr);
    REQUIRE(info.find_base(reflection::TypeId::from_name("missing")) == nullptr);

    REQUIRE_FALSE(registry.register_type(reflection::TypeInfo{}).has_value());
    REQUIRE(registry.register_type(reflection::TypeInfo{.id = reflection::TypeId::from_name("unnamed")})
                .error()
                .code == ErrorCode::InvalidArgument);
    REQUIRE(registry.register_type(info).has_value());
    REQUIRE(registry.register_type(info).error().code == ErrorCode::Conflict);

    auto by_name = registry.find_by_name("tessera::DummyVec3");
    REQUIRE(by_name.has_value());
    REQUIRE(by_name->members.size() == 3);
    auto by_id = registry.find(info.id);
    REQUIRE(by_id.has_value());
    REQUIRE(by_id->name == "tessera::DummyVec3");

    REQUIRE(registry.find(reflection::TypeId::from_name("missing")).error().code == ErrorCode::NotFound);
    REQUIRE(registry.find_by_name("missing").error().code == ErrorCode::NotFound);
    REQUIRE(registry.find_by_name("").error().code == ErrorCode::NotFound);
    REQUIRE(registry.search("DummyVec3").size() == 1);
}
