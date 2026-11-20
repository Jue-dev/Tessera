#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <unordered_map>

#include "FakeMemoryBackend.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/profile/profile.hpp"
#include "tessera/profile/profile_json.hpp"
#include "tessera/targets/targets.hpp"
#include "tessera/targets/target_profile_json.hpp"

namespace {

class InMemorySecretStore final : public tessera::profile::ISecretStore {
public:
    tessera::Result<std::string> store_secret(std::string_view secret_id,
                                              std::string_view plaintext) override {
        const std::string ref = "dpapi_ref:" + std::string(secret_id);
        secrets_[ref] = std::string(plaintext);
        return ref;
    }

    tessera::Result<std::string> load_secret(std::string_view secret_ref) const override {
        auto it = secrets_.find(std::string(secret_ref));
        if (it == secrets_.end()) {
            return tessera::fail(tessera::ErrorCode::NotFound, "InMemorySecretStore::load_secret");
        }
        return it->second;
    }

private:
    std::unordered_map<std::string, std::string> secrets_{};
};

} // namespace

TEST_CASE("Settings Profile layered precedence, atomic snapshot, migration, and JsonProfileStore",
          "[profile]") {
    using namespace tessera;
    using namespace tessera::profile;

    constexpr Key<std::int64_t> kTimeoutMs{"network.timeout_ms"};
    constexpr Key<std::string> kApiToken{"auth.api_token"};

    SettingsSchema schema(2, UnknownKeyPolicy::Reject);
    schema.add_definition({
        .key = "net.old_timeout",
        .renamed_to = "network.timeout_ms",
    });
    schema.add_definition({
        .key = "network.timeout_ms",
        .type = SettingValueType::Int64,
        .default_value = SettingValue{std::int64_t{1000}},
        .required = true,
        .min_numeric = 100.0,
        .max_numeric = 30000.0,
    });
    schema.add_definition({
        .key = "auth.api_token",
        .type = SettingValueType::String,
        .default_value = SettingValue{std::string("default-token")},
        .required = true,
        .is_secret = true,
    });

    const auto temp_dir = std::filesystem::temp_directory_path() / "tessera_profile_test";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    auto secret_store = std::make_shared<InMemorySecretStore>();
    auto store = std::make_shared<JsonProfileStore>(temp_dir, &schema, secret_store.get());
    ProfileManager mgr(schema, store, secret_store);

    // Register migration from schemaVersion 1 -> 2
    mgr.register_migration({
        .from_version = 1,
        .to_version = 2,
        .migrate = [](Profile& p) -> Status {
            if (auto* v = p.find("net.old_timeout")) {
                if (const auto* iv = std::get_if<std::int64_t>(v)) {
                    p.set("network.timeout_ms", SettingValue{*iv * 2});
                    p.erase("net.old_timeout");
                }
            }
            return ok();
        },
    });

    // BuiltIn default is active initially
    auto snap0 = mgr.snapshot();
    REQUIRE(snap0->get(kTimeoutMs).value() == 1000);
    REQUIRE(snap0->provenance("network.timeout_ms").value() == SettingLayer::BuiltIn);

    // Activate v1 profile -> migrates 1->2 and publishes new snapshot atomically
    Profile p1{};
    p1.id = "work";
    p1.name = "Work Profile";
    p1.schema_version = 1;
    p1.set("net.old_timeout", SettingValue{std::int64_t{1500}});
    p1.set("auth.api_token", SettingValue{std::string("super-secret-xyz")});

    auto act_res = mgr.activate_profile(p1);
    REQUIRE(act_res.has_value());
    REQUIRE(act_res->valid);

    auto snap1 = mgr.snapshot();
    REQUIRE(snap1->get(kTimeoutMs).value() == 3000);
    REQUIRE(snap1->provenance("network.timeout_ms").value() == SettingLayer::ActiveProfile);

    // RuntimeSession override takes highest precedence over ActiveProfile
    mgr.set_runtime_override("network.timeout_ms", SettingValue{std::int64_t{5000}});
    REQUIRE(mgr.snapshot()->get(kTimeoutMs).value() == 5000);
    REQUIRE(mgr.snapshot()->provenance("network.timeout_ms").value() == SettingLayer::RuntimeSession);
    mgr.clear_runtime_overrides();
    REQUIRE(mgr.snapshot()->get(kTimeoutMs).value() == 3000);

    // Invalid profile activation fails validation and preserves previous snapshot!
    Profile invalid_prof{};
    invalid_prof.id = "broken";
    invalid_prof.schema_version = 2;
    invalid_prof.set("network.timeout_ms", SettingValue{std::int64_t{5}}); // Below min 100
    auto bad_act = mgr.activate_profile(invalid_prof);
    REQUIRE(bad_act.has_value());
    REQUIRE_FALSE(bad_act->valid);
    REQUIRE(mgr.snapshot()->active_profile_id() == "work");
    REQUIRE(mgr.snapshot()->get(kTimeoutMs).value() == 3000);

    // Save active profile to JSON and verify secret is not stored in plaintext
    REQUIRE(mgr.save_active_profile().has_value());
    const auto raw_json =
        filesystem::read_file_utf8(temp_dir / "work.profile.json").value();
    REQUIRE(raw_json.find("super-secret-xyz") == std::string::npos);
    REQUIRE(raw_json.find("$secretRef") != std::string::npos);

    // Revision conflict detection on concurrent save
    Profile stale_copy = store->load("work").value();
    Profile fresh_copy = stale_copy;
    REQUIRE(store->save(fresh_copy).has_value());
    auto conflict_st = store->save(stale_copy);
    REQUIRE_FALSE(conflict_st.has_value());
    REQUIRE(conflict_st.error().code == ErrorCode::Conflict);

    std::filesystem::remove_all(temp_dir, ec);
}

TEST_CASE("Targets verification engine: exact build, stale, compatible build, needs review, ambiguous, and session cache",
          "[targets]") {
    using namespace tessera;
    using namespace tessera::targets;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x140000000ULL}, 0x4000, MemoryProtection::ExecuteReadWrite);

    // Place valid code pattern at RVA 0x1000 (VA 0x140001000): 48 8B 05 11 22 33 44 48 85 C0
    const std::array<std::byte, 10> sig_bytes{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
        std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}};
    backend->poke_bytes(Address{0x140001000ULL}, sig_bytes);

    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64, ProcessId{9000});

    TargetModuleContext mod_ctx{};
    mod_ctx.module_id = "main";
    mod_ctx.file_name = "Game.exe";
    mod_ctx.range = AddressRange{Address{0x140000000ULL}, 0x4000};
    mod_ctx.fingerprint = ModuleFingerprint{
        .module_id = "main",
        .file_name = "Game.exe",
        .architecture = TargetArch::X64,
        .size_of_image = 0x4000,
        .timestamp = 0x65000000,
        .checksum = 0x12345678,
        .sha256 = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff66660000111122223333",
    };
    mod_ctx.custom_sections.push_back(Section{
        .name = ".text",
        .rva = Rva{0x1000},
        .virtual_size = 0x2000,
        .characteristics = SectionCharacteristics::Code | SectionCharacteristics::Execute |
                           SectionCharacteristics::Read,
        .module_base = Address{0x140000000ULL},
    });

    TargetProfile profile{};
    profile.application.application_id = "com.example.game";
    profile.application.display_name = "Example Game";
    profile.application.executables = {"Game.exe"};

    TargetBuild b1{};
    b1.build_id = "win64-v1";
    b1.architecture = TargetArch::X64;
    b1.fingerprint.size_of_image = 0x4000;
    b1.fingerprint.sha256 = mod_ctx.fingerprint.sha256;
    b1.modules.push_back(mod_ctx.fingerprint);

    AddressEntry entry{};
    entry.id = "player.update_fn";
    entry.name = "Player::Update";
    entry.kind = AddressKind::Function;
    entry.module_id = "main";
    entry.primary = ResolutionRecipe{
        .strategy = ResolutionStrategy::Rva,
        .rva = Rva{0x1000},
    };
    entry.fallback = ResolutionRecipe{
        .strategy = ResolutionStrategy::Pattern,
        .pattern = "48 8B 05 ?? ?? ?? ?? 48 85 C0",
        .section = ".text",
        .match_count = 1,
        .result_offset = 0,
    };
    entry.validation.rules = {
        {.kind = ValidationRuleKind::ModuleRange, .required = true},
        {.kind = ValidationRuleKind::Section, .required = true, .value = ".text"},
        {.kind = ValidationRuleKind::MemoryExecutable, .required = true},
        {.kind = ValidationRuleKind::ExpectedBytes,
         .required = true,
         .value = "48 8B 05 ?? ?? ?? ?? 48 85 C0"},
    };
    b1.addresses.push_back(entry);
    profile.builds.push_back(b1);

    AddressResolver resolver{proc, {mod_ctx}};

    // 1. Exact build match + all required checks pass -> VerifiedExactBuild
    auto out1 = resolver.resolve_entry(profile, "player.update_fn");
    REQUIRE(out1.status == ResolutionStatus::VerifiedExactBuild);
    REQUIRE(out1.verified().has_value());
    REQUIRE(out1.verified()->address() == Address{0x140001000ULL});
    REQUIRE_FALSE(out1.from_session_cache);

    // Second lookup hits session cache
    auto out_cached = resolver.resolve_entry(profile, "player.update_fn");
    REQUIRE(out_cached.from_session_cache);
    REQUIRE(out_cached.verified().has_value());

    // 2. Corrupt bytes at RVA 0x1000 on exact build (without fallback) -> Stale (no VerifiedAddress!)
    resolver.invalidate_session_cache();
    profile.builds[0].addresses[0].fallback.reset();
    backend->poke_value<std::uint8_t>(Address{0x140001000ULL}, 0xCCu);
    auto out_stale = resolver.resolve_entry(profile, "player.update_fn");
    REQUIRE(out_stale.status == ResolutionStatus::Stale);
    REQUIRE_FALSE(out_stale.verified().has_value());

    // 3. New compatible build (different SHA256, code moved to RVA 0x1500) -> VerifiedCompatibleBuild
    //    and AutoPersistVerified appends a new TargetBuild while preserving win64-v1!
    profile.builds[0].addresses[0].fallback = entry.fallback;
    backend->poke_bytes(Address{0x140001500ULL}, sig_bytes);
    mod_ctx.fingerprint.sha256 = "9999999999999999999999999999999999999999999999999999999999999999";
    resolver.set_modules({mod_ctx});

    auto out_compat = resolver.resolve_entry(
        profile, "player.update_fn", PersistPolicy::AutoPersistVerified);
    REQUIRE(out_compat.status == ResolutionStatus::VerifiedCompatibleBuild);
    REQUIRE(out_compat.verified().has_value());
    REQUIRE(out_compat.verified()->address() == Address{0x140001500ULL});
    REQUIRE(out_compat.verified()->rva() == Rva{0x1500});
    REQUIRE(profile.builds.size() == 2);
    REQUIRE(profile.builds[1].addresses.size() == 1);
    REQUIRE(profile.builds[1].addresses[0].audit.has_value());

    // 4. Duplicate pattern match in .text -> Ambiguous (never verified!)
    profile.builds.pop_back();
    resolver.invalidate_session_cache();
    backend->poke_bytes(Address{0x140001800ULL}, sig_bytes);
    auto out_ambig = resolver.resolve_entry(profile, "player.update_fn");
    REQUIRE(out_ambig.status == ResolutionStatus::Ambiguous);
    REQUIRE_FALSE(out_ambig.verified().has_value());

    // 5. DiscoverySession captures and validates a new candidate address
    DiscoverySession disc{proc, mod_ctx};
    auto captured = disc.capture_and_verify(
        profile,
        DiscoveryCandidate{
            .entry_id = "discovered.fn",
            .name = "DiscoveredFn",
            .kind = AddressKind::Function,
            .module_id = "main",
            .address = Address{0x140001500ULL},
        });
    REQUIRE(captured.has_value());
    REQUIRE(captured->primary.rva == Rva{0x1500});
}

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
}
