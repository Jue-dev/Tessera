#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>
#include <unordered_map>

#include "FakeMemoryBackend.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/profile/profile.hpp"
#include "tessera/profile/profile_json.hpp"
#include "tessera/targets/targets.hpp"
#include "tessera/targets/target_profile_json.hpp"

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

    ResolutionTrace cache_trace;
    auto traced_cache = resolver.resolve_entry(
        profile, "player.update_fn", PersistPolicy::AskBeforePersist, nullptr, &cache_trace);
    REQUIRE(traced_cache.from_session_cache);
    REQUIRE(cache_trace.steps.back().stage == "Verified session cache");
    REQUIRE(cache_trace.steps.back().detail == "Resolved from verified session cache");

    resolver.invalidate_session_cache();
    ResolutionTrace exact_trace;
    auto out_traced = resolver.resolve_entry(
        profile, "player.update_fn", PersistPolicy::AskBeforePersist, nullptr, &exact_trace);
    REQUIRE(out_traced.status == ResolutionStatus::VerifiedExactBuild);
    REQUIRE_FALSE(exact_trace.steps.empty());
    REQUIRE(exact_trace.steps.back().stage == "Exact-build primary recipe");
    REQUIRE(exact_trace.steps.back().status == ResolutionStatus::VerifiedExactBuild);

    // 1b. A failed exact-build primary recipe must continue to a successful fallback.
    TargetProfile fallback_profile = profile;
    auto& fallback_entry = fallback_profile.builds[0].addresses[0];
    fallback_entry.primary.rva = Rva{0x5000};
    fallback_entry.fallback = entry.fallback;
    fallback_entry.validation.allow_compatible_build = true;
    resolver.invalidate_session_cache();
    ResolutionTrace fallback_trace;
    auto out_fallback = resolver.resolve_entry(
        fallback_profile, "player.update_fn", PersistPolicy::AskBeforePersist, nullptr, &fallback_trace);
    REQUIRE(out_fallback.status == ResolutionStatus::VerifiedCompatibleBuild);
    REQUIRE(out_fallback.verified().has_value());
    REQUIRE(out_fallback.candidate_address == Address{0x140001000ULL});
    REQUIRE(fallback_trace.steps.size() >= 2);
    REQUIRE(fallback_trace.steps[1].stage == "Exact-build primary recipe");
    REQUIRE(fallback_trace.steps.back().stage == "Fallback and compatible-build recipe");
    REQUIRE(fallback_trace.steps.back().status == ResolutionStatus::VerifiedCompatibleBuild);

    // A second lookup caches that verified fallback; rebinding the module at a new base invalidates it.
    auto cached_fallback = resolver.resolve_entry(fallback_profile, "player.update_fn");
    REQUIRE(cached_fallback.from_session_cache);
    constexpr std::uint64_t rebound_base = 0x160000000ULL;
    backend->map_region(Address{rebound_base}, 0x4000, MemoryProtection::ExecuteReadWrite);
    backend->poke_bytes(Address{rebound_base + 0x1000}, sig_bytes);
    TargetModuleContext rebound_ctx = mod_ctx;
    rebound_ctx.range = AddressRange{Address{rebound_base}, 0x4000};
    rebound_ctx.custom_sections[0].module_base = Address{rebound_base};
    resolver.set_modules({rebound_ctx});
    ResolutionTrace rebound_trace;
    auto rebound = resolver.resolve_entry(
        fallback_profile, "player.update_fn", PersistPolicy::AskBeforePersist, nullptr, &rebound_trace);
    REQUIRE_FALSE(rebound.from_session_cache);
    REQUIRE(rebound.status == ResolutionStatus::VerifiedCompatibleBuild);
    REQUIRE(rebound.candidate_address == Address{rebound_base + 0x1000});
    REQUIRE(rebound_trace.steps.back().stage == "Fallback and compatible-build recipe");

    // All recipes failing must leave a complete, terminal resolution trace.
    fallback_entry.fallback->pattern = "FF EE DD CC";
    resolver.invalidate_session_cache();
    ResolutionTrace failed_fallback_trace;
    auto failed_fallback = resolver.resolve_entry(
        fallback_profile, "player.update_fn", PersistPolicy::AskBeforePersist, nullptr, &failed_fallback_trace);
    REQUIRE(failed_fallback.status == ResolutionStatus::Stale);
    REQUIRE_FALSE(failed_fallback.verified().has_value());
    REQUIRE(failed_fallback_trace.steps.back().status == ResolutionStatus::Stale);
    REQUIRE(failed_fallback_trace.steps.back().detail.find("unavailable") != std::string::npos);

    // Restore the original module context and leave the original profile untouched for later cases.
    resolver.set_modules({mod_ctx});
    resolver.invalidate_session_cache();

    // 2. Corrupt bytes at RVA 0x1000 on exact build (without fallback) -> Stale (no VerifiedAddress!)
    resolver.invalidate_session_cache();
    profile.builds[0].addresses[0].fallback.reset();
    backend->poke_value<std::uint8_t>(Address{0x140001000ULL}, 0xCCu);
    ResolutionTrace stale_trace;
    auto out_stale = resolver.resolve_entry(
        profile, "player.update_fn", PersistPolicy::AskBeforePersist, nullptr, &stale_trace);
    REQUIRE(out_stale.status == ResolutionStatus::Stale);
    REQUIRE_FALSE(out_stale.verified().has_value());
    REQUIRE_FALSE(stale_trace.steps.empty());
    REQUIRE(stale_trace.steps.back().stage == "Exact-build primary recipe");
    REQUIRE(stale_trace.steps.back().detail.find("failed required validation") != std::string::npos);

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
