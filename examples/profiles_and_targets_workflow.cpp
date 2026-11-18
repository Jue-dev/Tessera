#include "tessera/tessera.hpp"

#include <iostream>
#include <memory>

int main() {
    using namespace tessera;
    using namespace tessera::profile;
    using namespace tessera::targets;

    std::cout << "=== Tessera Example 06: Settings Profiles, Target Profiles, Logging & Profiling ===\n\n";

    // 1. Structured Logger + MemorySink + ScopeTimer
    auto mem_sink = std::make_shared<logging::MemorySink>();
    auto logger = std::make_shared<logging::Logger>("TesseraApp", logging::LogLevel::Info);
    logger->add_sink(mem_sink);

    {
        profiling::ScopeTimer timer("WorkflowInit", [&](std::string_view name, auto elapsed) {
            logger->info("{} completed in {} ns", name, elapsed.count());
        });

        // 2. Layered Settings Profile (BuiltIn < ActiveProfile < RuntimeSession)
        constexpr Key<std::int64_t> kScanChunkSize{"scanner.chunk_size_kb"};
        SettingsSchema schema(1, UnknownKeyPolicy::Preserve);
        schema.add_definition({
            .key = "scanner.chunk_size_kb",
            .type = SettingValueType::Int64,
            .default_value = SettingValue{std::int64_t{64}},
            .required = true,
            .min_numeric = 4.0,
            .max_numeric = 4096.0,
        });

        ProfileManager prof_mgr(schema);
        std::cout << "[Profile]  Default chunk_size_kb = "
                  << prof_mgr.snapshot()->get(kScanChunkSize).value_or(0) << " KiB\n";

        Profile user_prof{};
        user_prof.id = "fast-scan";
        user_prof.name = "Fast Scan Profile";
        user_prof.schema_version = 1;
        user_prof.set("scanner.chunk_size_kb", SettingValue{std::int64_t{256}});
        (void)prof_mgr.activate_profile(user_prof);

        std::cout << "[Profile]  ActiveProfile chunk_size_kb = "
                  << prof_mgr.snapshot()->get(kScanChunkSize).value_or(0) << " KiB\n";

        // 3. TargetProfile with multi-strategy recipes (Pattern, RttiVTable, StringXref, PythonMethod)
        TargetProfile tp{};
        tp.application.application_id = "com.studio.samplegame";
        tp.application.display_name = "Sample Game Client";
        tp.application.executables = {"SampleGame.exe"};

        TargetBuild build{};
        build.build_id = "win64-1.0.0";
        build.architecture = TargetArch::X64;
        build.addresses.push_back(AddressEntry{
            .id = "player.vfunc_update",
            .name = "Player::Update (vtable[0])",
            .kind = AddressKind::Function,
            .module_id = "main",
            .primary =
                ResolutionRecipe{
                    .strategy = ResolutionStrategy::RttiVTable,
                    .class_name = "Game::Player",
                    .vtable_index = 0,
                },
            .fallback =
                ResolutionRecipe{
                    .strategy = ResolutionStrategy::PythonMethod,
                    .python_method = "chr.Update",
                },
        });
        tp.builds.push_back(build);

        if (auto jv = serialize_target_profile_to_json(tp)) {
            if (auto json_str = json::write(*jv, {.pretty = true})) {
                std::cout << "[Targets]  Serialized TargetProfile JSON (" << json_str->size()
                          << " bytes):\n"
                          << *json_str << "\n";
            }
        }
    }

    std::cout << "[Logger]   Captured " << mem_sink->records().size()
              << " structured log record(s): " << mem_sink->records().front().message << "\n";

    return 0;
}
