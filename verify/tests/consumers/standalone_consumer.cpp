#include <catch2/catch_test_macros.hpp>

#include "tessera/core/core.hpp"
#include "tessera/diagnostics/diagnostics.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/json/json.hpp"
#include "tessera/logging/logging.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/profile/profile.hpp"
#include "tessera/profile/profile_json.hpp"
#include "tessera/profiling/profiling.hpp"
#include "tessera/reflection/reflection.hpp"
#include "tessera/targets/target_profile.hpp"
#include "tessera/targets/target_profile_json.hpp"
#include "tessera/utility/utility.hpp"

// This test executable links ONLY Process/Memory-independent modules to prove
// architectural layer isolation (§3.1 Rule 2, §16, §17.8).
TEST_CASE("Standalone modules link and operate without Process or Memory", "[standalone]") {
    using namespace tessera::literals;

    constexpr auto pat = "48 8B 05 ?? ?? ?? ??"_sig;
    STATIC_REQUIRE(pat.size() == 7);

    tessera::profile::SettingsSchema schema(1);
    schema.add_definition({
        .key = "ui.scale",
        .type = tessera::profile::SettingValueType::Double,
        .default_value = tessera::profile::SettingValue{1.25},
        .required = true,
    });

    tessera::profile::ProfileManager mgr(schema);
    auto snap = mgr.snapshot();
    REQUIRE(snap != nullptr);
    auto scale = snap->get(tessera::profile::Key<double>{"ui.scale"});
    REQUIRE(scale.has_value());
    REQUIRE(*scale == 1.25);

    tessera::targets::TargetProfile tp{};
    tp.application.application_id = "com.example.standalone";
    tp.application.executables = {"App.exe"};
    REQUIRE(tessera::targets::validate_target_profile_schema(tp).has_value());
}
