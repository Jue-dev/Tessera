#include "tessera/profile/profile.hpp"

#include <algorithm>
#include <format>
#include <new>

namespace tessera::profile {

const SettingValue* Profile::find(std::string_view key) const noexcept {
    for (const auto& [k, v] : values) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}

SettingValue* Profile::find(std::string_view key) noexcept {
    for (auto& [k, v] : values) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}

void Profile::set(std::string key, SettingValue value) {
    for (auto& [k, v] : values) {
        if (k == key) {
            v = std::move(value);
            return;
        }
    }
    values.emplace_back(std::move(key), std::move(value));
}

bool Profile::erase(std::string_view key) noexcept {
    const auto it = std::remove_if(
        values.begin(), values.end(), [&](const auto& kv) { return kv.first == key; });
    if (it == values.end()) {
        return false;
    }
    values.erase(it, values.end());
    return true;
}

void SettingsSchema::add_definition(SettingDefinition def) {
    for (auto& existing : definitions_) {
        if (existing.key == def.key) {
            existing = std::move(def);
            return;
        }
    }
    definitions_.push_back(std::move(def));
}

const SettingDefinition* SettingsSchema::find_definition(std::string_view key) const noexcept {
    for (const auto& def : definitions_) {
        if (def.key == key) {
            return &def;
        }
    }
    return nullptr;
}

namespace {

[[nodiscard]] std::optional<double> as_numeric(const SettingValue& val) noexcept {
    if (const auto* i = std::get_if<std::int64_t>(&val)) {
        return static_cast<double>(*i);
    }
    if (const auto* u = std::get_if<std::uint64_t>(&val)) {
        return static_cast<double>(*u);
    }
    if (const auto* d = std::get_if<double>(&val)) {
        return *d;
    }
    return std::nullopt;
}

[[nodiscard]] bool type_matches(const SettingValue& val, SettingValueType expected) noexcept {
    if (value_type_of(val) == expected) {
        return true;
    }
    // Allow non-negative int64 to satisfy UInt64 and integer values to satisfy Double
    if (expected == SettingValueType::UInt64) {
        if (const auto* i = std::get_if<std::int64_t>(&val)) {
            return *i >= 0;
        }
    }
    if (expected == SettingValueType::Double) {
        return std::holds_alternative<std::int64_t>(val) ||
               std::holds_alternative<std::uint64_t>(val);
    }
    return false;
}

void coerce_numeric_type(SettingValue& val, SettingValueType expected) {
    if (expected == SettingValueType::UInt64) {
        if (const auto* i = std::get_if<std::int64_t>(&val); i != nullptr && *i >= 0) {
            val = static_cast<std::uint64_t>(*i);
        }
    } else if (expected == SettingValueType::Double) {
        if (const auto* i = std::get_if<std::int64_t>(&val)) {
            val = static_cast<double>(*i);
        } else if (const auto* u = std::get_if<std::uint64_t>(&val)) {
            val = static_cast<double>(*u);
        }
    }
}

} // namespace

SchemaValidationReport SettingsSchema::validate_and_normalize(Profile& profile) const {
    SchemaValidationReport report{};

    // Step 1: Handle renamed/deprecated keys
    for (const auto& def : definitions_) {
        if (!def.renamed_to.empty()) {
            if (auto* old_val = profile.find(def.key)) {
                SettingValue moved = std::move(*old_val);
                profile.erase(def.key);
                if (profile.find(def.renamed_to) == nullptr) {
                    profile.set(def.renamed_to, std::move(moved));
                }
                report.warnings.push_back(
                    std::format("Key '{}' is renamed to '{}'", def.key, def.renamed_to));
            }
        }
    }

    // Step 2: Check unknown keys according to UnknownKeyPolicy
    for (auto it = profile.values.begin(); it != profile.values.end();) {
        const auto* def = find_definition(it->first);
        if (def == nullptr) {
            if (unknown_policy_ == UnknownKeyPolicy::Reject) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = it->first,
                    .message = "Unknown setting key is not allowed by schema",
                });
                ++it;
            } else if (unknown_policy_ == UnknownKeyPolicy::Ignore) {
                it = profile.values.erase(it);
            } else {
                ++it; // Preserve
            }
        } else {
            if (def->deprecated) {
                report.warnings.push_back(std::format("Key '{}' is deprecated", def->key));
            }
            ++it;
        }
    }

    // Step 3: Apply defaults and validate each defined setting
    for (const auto& def : definitions_) {
        if (!def.renamed_to.empty()) {
            continue;
        }
        auto* val_ptr = profile.find(def.key);
        if (val_ptr == nullptr) {
            if (def.default_value.has_value()) {
                profile.set(def.key, *def.default_value);
                val_ptr = profile.find(def.key);
            } else if (def.required) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = "Required setting is missing",
                });
                continue;
            } else {
                continue;
            }
        }

        if (!type_matches(*val_ptr, def.type)) {
            report.valid = false;
            report.issues.push_back(ValidationIssue{
                .key_path = def.key,
                .message = "Setting value has incompatible type",
            });
            continue;
        }
        coerce_numeric_type(*val_ptr, def.type);

        if (auto num = as_numeric(*val_ptr)) {
            if (def.min_numeric.has_value() && *num < *def.min_numeric) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = std::format("Value {} is below minimum {}", *num, *def.min_numeric),
                });
            }
            if (def.max_numeric.has_value() && *num > *def.max_numeric) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = std::format("Value {} exceeds maximum {}", *num, *def.max_numeric),
                });
            }
        }

        if (const auto* str = std::get_if<std::string>(val_ptr)) {
            if (def.min_length.has_value() && str->size() < *def.min_length) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = "String value is shorter than min_length",
                });
            }
            if (def.max_length.has_value() && str->size() > *def.max_length) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = "String value exceeds max_length",
                });
            }
            if (!def.allowed_values.empty()) {
                const bool found = std::find(def.allowed_values.begin(),
                                             def.allowed_values.end(),
                                             *str) != def.allowed_values.end();
                if (!found) {
                    report.valid = false;
                    report.issues.push_back(ValidationIssue{
                        .key_path = def.key,
                        .message = "Value is not in allowed_values list",
                    });
                }
            }
        }

        if (const auto* list = std::get_if<StringList>(val_ptr)) {
            if (def.min_length.has_value() && list->size() < *def.min_length) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = "StringList has fewer items than min_length",
                });
            }
            if (def.max_length.has_value() && list->size() > *def.max_length) {
                report.valid = false;
                report.issues.push_back(ValidationIssue{
                    .key_path = def.key,
                    .message = "StringList exceeds max_length",
                });
            }
        }
    }

    return report;
}

ProfileManager::ProfileManager(SettingsSchema schema,
                               std::shared_ptr<ProfileStore> store,
                               std::shared_ptr<ISecretStore> secret_store)
    : schema_(std::move(schema)),
      store_(std::move(store)),
      secret_store_(std::move(secret_store)) {
    // Initialize BuiltIn layer from schema defaults
    std::vector<std::pair<std::string, SettingValue>> builtins;
    for (const auto& def : schema_.definitions()) {
        if (def.default_value.has_value()) {
            builtins.emplace_back(def.key, *def.default_value);
        }
    }
    layers_[static_cast<std::size_t>(SettingLayer::BuiltIn)] = std::move(builtins);
    active_profile_.id = "default";
    active_profile_.name = "Default";
    active_profile_.schema_version = schema_.schema_version();
    active_snapshot_.store(build_snapshot_locked(active_profile_), std::memory_order_release);
}

void ProfileManager::register_migration(MigrationStep step) {
    const std::lock_guard<std::mutex> lock(mutex_);
    migrations_.push_back(std::move(step));
}

void ProfileManager::set_layer_values(
    SettingLayer layer,
    std::vector<std::pair<std::string, SettingValue>> values) {
    const std::lock_guard<std::mutex> lock(mutex_);
    layers_[static_cast<std::size_t>(layer)] = std::move(values);
    active_snapshot_.store(build_snapshot_locked(active_profile_), std::memory_order_release);
}

void ProfileManager::set_runtime_override(std::string key, SettingValue value) {
    const std::lock_guard<std::mutex> lock(mutex_);
    auto& rt = layers_[static_cast<std::size_t>(SettingLayer::RuntimeSession)];
    bool updated = false;
    for (auto& [k, v] : rt) {
        if (k == key) {
            v = std::move(value);
            updated = true;
            break;
        }
    }
    if (!updated) {
        rt.emplace_back(std::move(key), std::move(value));
    }
    active_snapshot_.store(build_snapshot_locked(active_profile_), std::memory_order_release);
}

void ProfileManager::clear_runtime_overrides() {
    const std::lock_guard<std::mutex> lock(mutex_);
    layers_[static_cast<std::size_t>(SettingLayer::RuntimeSession)].clear();
    active_snapshot_.store(build_snapshot_locked(active_profile_), std::memory_order_release);
}

Status ProfileManager::run_migrations_locked(Profile& profile) {
    while (profile.schema_version < schema_.schema_version()) {
        bool progressed = false;
        for (auto& step : migrations_) {
            if (step.from_version == profile.schema_version &&
                step.to_version > step.from_version) {
                auto st = step.migrate(profile);
                if (!st) {
                    return st;
                }
                profile.schema_version = step.to_version;
                progressed = true;
                break;
            }
        }
        if (!progressed) {
            return fail(ErrorCode::ValidationFailed,
                        "ProfileManager::run_migrations",
                        0,
                        std::format("No migration path from schemaVersion {} to {}",
                                    profile.schema_version,
                                    schema_.schema_version()));
        }
    }
    return ok();
}

std::shared_ptr<const ProfileSnapshot> ProfileManager::build_snapshot_locked(
    const Profile& active) const {
    std::vector<ProvenanceEntry> resolved;

    const auto apply_kv = [&](const std::string& key,
                              const SettingValue& val,
                              SettingLayer layer) {
        for (auto& entry : resolved) {
            if (entry.key == key) {
                entry.value = val;
                entry.source_layer = layer;
                return;
            }
        }
        resolved.push_back(ProvenanceEntry{
            .key = key,
            .value = val,
            .source_layer = layer,
        });
    };

    // Precedence: BuiltIn < User < Machine < Project < ActiveProfile < Environment < CommandLine < RuntimeSession
    for (std::size_t idx = 0; idx < 8; ++idx) {
        const auto layer = static_cast<SettingLayer>(idx);
        if (layer == SettingLayer::ActiveProfile) {
            for (const auto& [k, v] : active.values) {
                apply_kv(k, v, SettingLayer::ActiveProfile);
            }
        } else {
            for (const auto& [k, v] : layers_[idx]) {
                apply_kv(k, v, layer);
            }
        }
    }

    return std::make_shared<const ProfileSnapshot>(active.id, active.revision, std::move(resolved));
}

Result<SchemaValidationReport> ProfileManager::activate_profile(Profile profile) {
    try {
        const std::lock_guard<std::mutex> lock(mutex_);
        auto mig_st = run_migrations_locked(profile);
        if (!mig_st) {
            return std::unexpected(mig_st.error());
        }

        auto report = schema_.validate_and_normalize(profile);
        if (!report.valid) {
            return report; // Old profile & snapshot remain untouched!
        }

        active_profile_ = std::move(profile);
        layers_[static_cast<std::size_t>(SettingLayer::ActiveProfile)] = active_profile_.values;
        auto new_snap = build_snapshot_locked(active_profile_);
        active_snapshot_.store(std::move(new_snap), std::memory_order_release);
        return report;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "ProfileManager::activate_profile");
    }
}

Result<SchemaValidationReport> ProfileManager::load_and_activate(std::string_view profile_id) {
    if (!store_) {
        return fail(ErrorCode::BackendUnavailable,
                    "ProfileManager::load_and_activate",
                    0,
                    "No ProfileStore configured");
    }
    auto loaded = store_->load(profile_id);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }
    return activate_profile(std::move(*loaded));
}

Status ProfileManager::save_active_profile() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (!store_) {
        return fail(ErrorCode::BackendUnavailable, "ProfileManager::save_active_profile");
    }
    auto st = store_->save(active_profile_);
    if (!st) {
        return st;
    }
    active_snapshot_.store(build_snapshot_locked(active_profile_), std::memory_order_release);
    return ok();
}

Result<Profile> ProfileManager::clone_active_profile(std::string new_id,
                                                     std::string new_name) const {
    if (new_id.empty()) {
        return fail(ErrorCode::InvalidArgument, "ProfileManager::clone_active_profile");
    }
    try {
        const std::lock_guard<std::mutex> lock(mutex_);
        Profile copy = active_profile_;
        copy.id = std::move(new_id);
        copy.name = std::move(new_name);
        copy.revision = 1;
        return copy;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "ProfileManager::clone_active_profile");
    }
}

Result<Profile> ProfileManager::active_profile() const {
    try {
        const std::lock_guard<std::mutex> lock(mutex_);
        return active_profile_;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "ProfileManager::active_profile");
    }
}

} // namespace tessera::profile
