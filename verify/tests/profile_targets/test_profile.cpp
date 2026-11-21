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


TEST_CASE("Profile JSON rejects secret-reference and schema boundary violations", "[profile][json][schema]") {
    using namespace tessera;
    using namespace tessera::profile;

    class SecretStore final : public ISecretStore {
    public:
        Result<std::string> store_secret(std::string_view, std::string_view value) override {
            stored = std::string(value);
            return std::string("secret:token");
        }
        Result<std::string> load_secret(std::string_view ref) const override {
            if (ref != "secret:token") {
                return fail(ErrorCode::NotFound, "SecretStore::load_secret");
            }
            return stored;
        }
        std::string stored{};
    } secret_store;

    SettingsSchema schema{3, UnknownKeyPolicy::Reject};
    schema.add_definition(SettingDefinition{
        .key = "service.token", .type = SettingValueType::String, .required = true, .is_secret = true});
    schema.add_definition(SettingDefinition{
        .key = "service.timeout", .type = SettingValueType::UInt64,
        .default_value = SettingValue{std::uint64_t{1000}}, .required = true,
        .min_numeric = 10.0, .max_numeric = 60000.0});

    Profile profile{};
    profile.id = "boundary-profile";
    profile.schema_version = 3;
    profile.set("service.token", SettingValue{std::string("do-not-persist")});
    profile.set("service.timeout", SettingValue{std::uint64_t{60000}});
    profile.set("service.labels", SettingValue{StringList{"one", "two", "three"}});

    auto encoded = serialize_profile_to_json(profile, &schema, &secret_store);
    REQUIRE(encoded.has_value());
    auto decoded = deserialize_profile_from_json(*encoded, &schema, &secret_store);
    REQUIRE(decoded.has_value());
    REQUIRE(std::get<std::string>(*decoded->find("service.token")) == "do-not-persist");
    REQUIRE(std::get<std::uint64_t>(*decoded->find("service.timeout")) == 60000);
    REQUIRE(std::get<StringList>(*decoded->find("service.labels")).size() == 3);

    auto missing_store = deserialize_profile_from_json(*encoded, &schema, nullptr);
    REQUIRE_FALSE(missing_store.has_value());
    REQUIRE(missing_store.error().code == ErrorCode::ValidationFailed);

    auto invalid_secret_ref = *encoded;
    auto* values = invalid_secret_ref.find("values");
    REQUIRE(values != nullptr);
    auto* secret_value = values->find("service.token");
    REQUIRE(secret_value != nullptr);
    secret_value->set("$secretRef", "secret:missing");
    auto unresolved = deserialize_profile_from_json(invalid_secret_ref, &schema, &secret_store);
    REQUIRE_FALSE(unresolved.has_value());
    REQUIRE(unresolved.error().code == ErrorCode::NotFound);

    auto plaintext_secret = *encoded;
    auto* plaintext_values = plaintext_secret.find("values");
    REQUIRE(plaintext_values != nullptr);
    plaintext_values->set("service.token", "plaintext");
    auto leaked_secret = deserialize_profile_from_json(plaintext_secret, &schema, &secret_store);
    REQUIRE_FALSE(leaked_secret.has_value());
    REQUIRE(leaked_secret.error().code == ErrorCode::ValidationFailed);

    auto incompatible_format = *encoded;
    incompatible_format.set("formatVersion", std::uint64_t{0});
    REQUIRE_FALSE(deserialize_profile_from_json(incompatible_format, &schema, &secret_store).has_value());

    Profile invalid_schema{};
    invalid_schema.id = "invalid";
    invalid_schema.schema_version = 3;
    invalid_schema.set("service.timeout", SettingValue{std::string("not-an-integer")});
    invalid_schema.set("service.unknown", SettingValue{true});
    const auto report = schema.validate_and_normalize(invalid_schema);
    REQUIRE_FALSE(report.valid);
    REQUIRE(report.issues.size() >= 2);
}
