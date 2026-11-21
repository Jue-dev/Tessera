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
