#include "tessera/targets/target_runtime.hpp"

#include <algorithm>
#include <utility>

#include "tessera/memory/memory_reader.hpp"
#include "tessera/resolver/resolver.hpp"
#include "tessera/utility/hex.hpp"

namespace tessera::targets {

Result<AddressEntry> DiscoverySession::capture_and_verify(
    TargetProfile& profile,
    const DiscoveryCandidate& candidate) const {
    if (candidate.entry_id.empty() || candidate.address.is_null()) {
        return fail(ErrorCode::InvalidArgument, "DiscoverySession::capture_and_verify");
    }
    if (!mod_ctx_.range.contains(candidate.address)) {
        return fail(ErrorCode::OutOfRange,
                    "DiscoverySession::capture_and_verify",
                    0,
                    "Candidate address is outside target module range");
    }

    auto rva_res = mod_ctx_.range.to_rva(candidate.address);
    if (!rva_res) {
        return std::unexpected(rva_res.error());
    }

    MemoryReader reader{process_};
    const std::size_t ctx_len = (std::max)(candidate.expected_bytes_len, std::size_t{4});
    auto ctx_bytes = reader.read_bytes(candidate.address, ctx_len);
    if (!ctx_bytes) {
        return std::unexpected(ctx_bytes.error());
    }

    AddressEntry entry{};
    entry.id = candidate.entry_id;
    entry.name = candidate.name.empty() ? candidate.entry_id : candidate.name;
    entry.kind = candidate.kind;
    entry.module_id = candidate.module_id;
    entry.value = candidate.value;
    entry.primary = ResolutionRecipe{
        .strategy = ResolutionStrategy::Rva,
        .rva = *rva_res,
    };

    if (!candidate.fallback_pattern.empty()) {
        entry.fallback = ResolutionRecipe{
            .strategy = ResolutionStrategy::Pattern,
            .pattern = candidate.fallback_pattern,
            .match_count = 1,
            .result_offset = candidate.fallback_result_offset,
        };
    }

    entry.validation = default_validation_policy_for(candidate.kind);

    // Capture section rule if candidate falls inside a known section
    for (const auto& s : mod_ctx_.custom_sections) {
        if (s.range().contains(candidate.address)) {
            entry.validation.rules.push_back(ValidationRule{
                .kind = ValidationRuleKind::Section,
                .required = true,
                .value = s.name,
            });
            break;
        }
    }

    if (candidate.kind == AddressKind::Function) {
        entry.validation.rules.push_back(ValidationRule{
            .kind = ValidationRuleKind::ExpectedBytes,
            .required = true,
            .value = hex::encode(*ctx_bytes),
        });
    }

    // Verify entry against current process before adding to profile
    TargetProfile temp_profile = profile;
    const TargetArch arch =
        (process_.architecture() == Architecture::X64) ? TargetArch::X64 : TargetArch::X86;

    TargetBuild build{};
    build.build_id = "discovered-build";
    build.architecture = arch;
    build.fingerprint.size_of_image = mod_ctx_.fingerprint.size_of_image;
    build.fingerprint.sha256 = mod_ctx_.fingerprint.sha256;
    build.modules.push_back(mod_ctx_.fingerprint);
    build.addresses.push_back(entry);
    temp_profile.builds.push_back(build);

    auto schema_st = validate_target_profile_schema(temp_profile);
    if (!schema_st) {
        return std::unexpected(schema_st.error());
    }

    AddressResolver resolver{process_, {mod_ctx_}};
    auto outcome = resolver.resolve_entry(temp_profile, entry.id, PersistPolicy::ReadOnly);
    if (!outcome.verified().has_value()) {
        return fail(ErrorCode::ValidationFailed,
                    "DiscoverySession::capture_and_verify",
                    0,
                    "Discovered candidate failed mandatory validation checks");
    }

    // Add to profile
    if (profile.builds.empty()) {
        profile.builds.push_back(std::move(build));
    } else {
        profile.builds.front().addresses.push_back(entry);
    }
    return entry;
}


} // namespace tessera::targets
