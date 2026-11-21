#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <unordered_map>

#include "FakeMemoryBackend.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/profile/profile.hpp"
#include "tessera/profile/profile_json.hpp"
#include "tessera/targets/targets.hpp"
#include "tessera/targets/target_profile_json.hpp"

TEST_CASE("Target profile JSON rejects malformed schema and round-trips", "[targets][json]") {
    using namespace tessera;
    using namespace tessera::targets;

    TargetProfile profile{};
    profile.application.application_id = "example.application";
    profile.application.display_name = "Example";
    profile.application.executables = {"example.exe"};

    TargetBuild build{};
    build.build_id = "build-1";
    build.architecture = TargetArch::X64;
    build.fingerprint.file_version = "1.2.3";
    build.fingerprint.timestamp = 0x12345678;

    ModuleFingerprint module{};
    module.module_id = "main";
    module.file_name = "example.exe";
    module.architecture = TargetArch::X64;
    module.size_of_image = 0x20000;
    build.modules.push_back(module);

    AddressEntry entry{};
    entry.id = "entry.main";
    entry.name = "MainEntry";
    entry.module_id = "main";
    entry.kind = AddressKind::Function;
    entry.primary.strategy = ResolutionStrategy::Rva;
    entry.primary.rva = Rva{0x1234};
    entry.validation.rules.push_back(ValidationRule{
        .kind = ValidationRuleKind::ModuleRange,
        .required = true,
    });
    build.addresses.push_back(entry);
    profile.builds.push_back(build);

    auto encoded = serialize_target_profile_to_json(profile);
    REQUIRE(encoded.has_value());
    auto decoded = deserialize_target_profile_from_json(*encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->application.application_id == profile.application.application_id);
    REQUIRE(decoded->builds.size() == 1);
    REQUIRE(decoded->builds[0].modules.size() == 1);
    REQUIRE(decoded->builds[0].addresses.size() == 1);
    REQUIRE(decoded->builds[0].addresses[0].primary.rva.value() == 0x1234);

    auto missing_application = json::JsonValue::make_object();
    auto app = json::JsonValue::make_object();
    app.set("executables", json::JsonValue::Array{json::JsonValue{"example.exe"}});
    missing_application.set("application", std::move(app));
    REQUIRE_FALSE(deserialize_target_profile_from_json(missing_application).has_value());

    auto wrong_type_application = json::JsonValue::make_object();
    auto wrong_app = json::JsonValue::make_object();
    wrong_app.set("applicationId", 42);
    wrong_app.set("executables", json::JsonValue::Array{json::JsonValue{"example.exe"}});
    wrong_type_application.set("application", std::move(wrong_app));
    REQUIRE_FALSE(deserialize_target_profile_from_json(wrong_type_application).has_value());

    auto incompatible_version = *encoded;
    incompatible_version.set("formatVersion", std::uint64_t{0});
    REQUIRE_FALSE(deserialize_target_profile_from_json(incompatible_version).has_value());

    auto invalid_architecture = *encoded;
    auto* builds = invalid_architecture.find("builds");
    REQUIRE(builds != nullptr);
    (*builds->as_array())[0].set("architecture", "arm64");
    REQUIRE_FALSE(deserialize_target_profile_from_json(invalid_architecture).has_value());

    auto conflicting_entry = *encoded;
    auto* conflict_builds = conflicting_entry.find("builds");
    REQUIRE(conflict_builds != nullptr);
    auto* addresses = (*conflict_builds->as_array())[0].find("addresses");
    REQUIRE(addresses != nullptr);
    addresses->as_array()->push_back((*addresses->as_array())[0]);
    REQUIRE_FALSE(deserialize_target_profile_from_json(conflicting_entry).has_value());

    auto incomplete_module = *encoded;
    auto* module_builds = incomplete_module.find("builds");
    REQUIRE(module_builds != nullptr);
    auto* modules = (*module_builds->as_array())[0].find("modules");
    REQUIRE(modules != nullptr);
    modules->as_array()->clear();
    REQUIRE_FALSE(deserialize_target_profile_from_json(incomplete_module).has_value());
}
