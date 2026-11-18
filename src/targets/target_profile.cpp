#include "tessera/targets/target_profile.hpp"

#include <algorithm>
#include <format>

#include "tessera/utility/string.hpp"

namespace tessera::targets {

ValidationPolicy default_validation_policy_for(AddressKind kind) {
    ValidationPolicy policy{};
    policy.minimum_unique_candidates = 1;
    policy.rules.push_back(ValidationRule{
        .kind = ValidationRuleKind::ModuleRange,
        .required = true,
    });

    switch (kind) {
        case AddressKind::Function:
        case AddressKind::Export:
            policy.rules.push_back(ValidationRule{
                .kind = ValidationRuleKind::MemoryExecutable,
                .required = true,
            });
            break;
        case AddressKind::Pointer:
        case AddressKind::VTable:
            policy.rules.push_back(ValidationRule{
                .kind = ValidationRuleKind::MemoryReadable,
                .required = true,
            });
            policy.rules.push_back(ValidationRule{
                .kind = ValidationRuleKind::PointerSanity,
                .required = true,
            });
            break;
        case AddressKind::Global:
        case AddressKind::Object:
        case AddressKind::Field:
        case AddressKind::Data:
            policy.rules.push_back(ValidationRule{
                .kind = ValidationRuleKind::MemoryReadable,
                .required = true,
            });
            break;
    }
    return policy;
}

bool ModuleFingerprint::matches_strong(const ModuleFingerprint& other) const noexcept {
    if (architecture != other.architecture) {
        return false;
    }
    if (!sha256.empty() && !other.sha256.empty()) {
        if (!utility::ascii_iequals(sha256, other.sha256)) {
            return false;
        }
    }
    if (!codeview_guid.empty() && !other.codeview_guid.empty()) {
        if (!utility::ascii_iequals(codeview_guid, other.codeview_guid) ||
            codeview_age != other.codeview_age) {
            return false;
        }
    }
    return matches_fast(other);
}

bool ModuleFingerprint::matches_fast(const ModuleFingerprint& other) const noexcept {
    if (architecture != other.architecture) {
        return false;
    }
    if (size_of_image != 0 && other.size_of_image != 0 && size_of_image != other.size_of_image) {
        return false;
    }
    if (timestamp != 0 && other.timestamp != 0 && timestamp != other.timestamp) {
        return false;
    }
    if (checksum != 0 && other.checksum != 0 && checksum != other.checksum) {
        return false;
    }
    return true;
}

bool BuildFingerprint::matches(const BuildFingerprint& other) const noexcept {
    if (!sha256.empty() && !other.sha256.empty()) {
        if (!utility::ascii_iequals(sha256, other.sha256)) {
            return false;
        }
    }
    if (!codeview_guid.empty() && !other.codeview_guid.empty()) {
        if (!utility::ascii_iequals(codeview_guid, other.codeview_guid) ||
            codeview_age != other.codeview_age) {
            return false;
        }
    }
    if (size_of_image != 0 && other.size_of_image != 0 && size_of_image != other.size_of_image) {
        return false;
    }
    if (timestamp != 0 && other.timestamp != 0 && timestamp != other.timestamp) {
        return false;
    }
    return true;
}

const ModuleFingerprint* TargetBuild::find_module(std::string_view module_id) const noexcept {
    for (const auto& m : modules) {
        if (m.module_id == module_id) {
            return &m;
        }
    }
    return nullptr;
}

const AddressEntry* TargetBuild::find_address(std::string_view entry_id) const noexcept {
    for (const auto& a : addresses) {
        if (a.id == entry_id) {
            return &a;
        }
    }
    return nullptr;
}

AddressEntry* TargetBuild::find_address(std::string_view entry_id) noexcept {
    for (auto& a : addresses) {
        if (a.id == entry_id) {
            return &a;
        }
    }
    return nullptr;
}

const TargetBuild* TargetProfile::find_build(std::string_view build_id) const noexcept {
    for (const auto& b : builds) {
        if (b.build_id == build_id) {
            return &b;
        }
    }
    return nullptr;
}

TargetBuild* TargetProfile::find_build(std::string_view build_id) noexcept {
    for (auto& b : builds) {
        if (b.build_id == build_id) {
            return &b;
        }
    }
    return nullptr;
}

Status validate_target_profile_schema(const TargetProfile& profile) {
    if (profile.format_version == 0 || profile.profile_version == 0) {
        return fail(ErrorCode::ValidationFailed,
                    "validate_target_profile_schema",
                    0,
                    "formatVersion and profileVersion must be >= 1");
    }
    if (profile.application.application_id.empty()) {
        return fail(ErrorCode::ValidationFailed,
                    "validate_target_profile_schema",
                    0,
                    "applicationId cannot be empty");
    }
    if (profile.application.executables.empty()) {
        return fail(ErrorCode::ValidationFailed,
                    "validate_target_profile_schema",
                    0,
                    "application.executables cannot be empty");
    }

    for (std::size_t bi = 0; bi < profile.builds.size(); ++bi) {
        const auto& b = profile.builds[bi];
        if (b.build_id.empty()) {
            return fail(ErrorCode::ValidationFailed,
                        "validate_target_profile_schema",
                        0,
                        "Build has empty buildId");
        }
        for (std::size_t bj = bi + 1; bj < profile.builds.size(); ++bj) {
            if (profile.builds[bj].build_id == b.build_id) {
                return fail(ErrorCode::ValidationFailed,
                            "validate_target_profile_schema",
                            0,
                            std::format("Duplicate buildId '{}'", b.build_id));
            }
        }
        if (b.modules.empty()) {
            return fail(ErrorCode::ValidationFailed,
                        "validate_target_profile_schema",
                        0,
                        std::format("Build '{}' must define at least one module", b.build_id));
        }

        for (std::size_t ai = 0; ai < b.addresses.size(); ++ai) {
            const auto& entry = b.addresses[ai];
            if (entry.id.empty()) {
                return fail(ErrorCode::ValidationFailed,
                            "validate_target_profile_schema",
                            0,
                            "AddressEntry has empty id");
            }
            for (std::size_t aj = ai + 1; aj < b.addresses.size(); ++aj) {
                if (b.addresses[aj].id == entry.id) {
                    return fail(ErrorCode::ValidationFailed,
                                "validate_target_profile_schema",
                                0,
                                std::format("Duplicate address id '{}' in build '{}'", entry.id, b.build_id));
                }
            }
            if (b.find_module(entry.module_id) == nullptr) {
                return fail(ErrorCode::ValidationFailed,
                            "validate_target_profile_schema",
                            0,
                            std::format("AddressEntry '{}' references unknown moduleId '{}'",
                                        entry.id,
                                        entry.module_id));
            }
            bool has_required_rule = false;
            for (const auto& r : entry.validation.rules) {
                if (r.required) {
                    has_required_rule = true;
                    break;
                }
            }
            if (!has_required_rule) {
                return fail(ErrorCode::ValidationFailed,
                            "validate_target_profile_schema",
                            0,
                            std::format("AddressEntry '{}' must have at least one required validation rule",
                                        entry.id));
            }
        }
    }

    return ok();
}

} // namespace tessera::targets
