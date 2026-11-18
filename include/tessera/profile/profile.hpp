#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "tessera/core/result.hpp"

namespace tessera::profile {

using StringList = std::vector<std::string>;

using SettingValue = std::variant<bool,
                                  std::int64_t,
                                  std::uint64_t,
                                  double,
                                  std::string,
                                  StringList>;

enum class SettingValueType : std::uint8_t {
    Bool = 0,
    Int64 = 1,
    UInt64 = 2,
    Double = 3,
    String = 4,
    StringList = 5,
};

[[nodiscard]] constexpr SettingValueType value_type_of(const SettingValue& v) noexcept {
    return static_cast<SettingValueType>(v.index());
}

// Compile-time typed setting key, e.g. constexpr Key<std::int64_t> kTimeoutMs{"network.timeout_ms"};
template <class T>
struct Key {
    std::string_view name{};
    constexpr explicit Key(std::string_view key_name) noexcept : name(key_name) {}
};

enum class UnknownKeyPolicy : std::uint8_t {
    Reject,
    Ignore,
    Preserve,
};

enum class SettingLayer : std::uint8_t {
    BuiltIn = 0,
    User = 1,
    Machine = 2,
    Project = 3,
    ActiveProfile = 4,
    Environment = 5,
    CommandLine = 6,
    RuntimeSession = 7,
};

struct SettingDefinition {
    std::string key{};
    SettingValueType type = SettingValueType::String;
    std::optional<SettingValue> default_value{};
    bool required = false;
    std::optional<double> min_numeric{};
    std::optional<double> max_numeric{};
    std::optional<std::size_t> min_length{};
    std::optional<std::size_t> max_length{};
    std::vector<std::string> allowed_values{};
    std::string description{};
    bool deprecated = false;
    std::string renamed_to{};
    bool is_secret = false;
};

struct ValidationIssue {
    std::string key_path{};
    std::string message{};
};

struct SchemaValidationReport {
    bool valid = true;
    std::vector<ValidationIssue> issues{};
    std::vector<std::string> warnings{};
};

struct Profile {
    std::string id{};
    std::string name{};
    std::string description{};
    std::vector<std::string> tags{};
    std::uint32_t format_version = 1;
    std::uint32_t schema_version = 1;
    std::uint64_t revision = 1;
    std::vector<std::pair<std::string, SettingValue>> values{};

    [[nodiscard]] const SettingValue* find(std::string_view key) const noexcept;
    [[nodiscard]] SettingValue* find(std::string_view key) noexcept;
    void set(std::string key, SettingValue value);
    bool erase(std::string_view key) noexcept;
};

class SettingsSchema {
public:
    explicit SettingsSchema(std::uint32_t schema_version = 1,
                            UnknownKeyPolicy unknown_policy = UnknownKeyPolicy::Reject) noexcept
        : schema_version_(schema_version), unknown_policy_(unknown_policy) {}

    void add_definition(SettingDefinition def);

    [[nodiscard]] std::uint32_t schema_version() const noexcept { return schema_version_; }
    [[nodiscard]] UnknownKeyPolicy unknown_key_policy() const noexcept { return unknown_policy_; }
    [[nodiscard]] std::span<const SettingDefinition> definitions() const noexcept {
        return definitions_;
    }
    [[nodiscard]] const SettingDefinition* find_definition(std::string_view key) const noexcept;

    // Validates and normalizes `profile` (applies renamed_to mappings, unknown key policy, and constraints).
    [[nodiscard]] SchemaValidationReport validate_and_normalize(Profile& profile) const;

private:
    std::uint32_t schema_version_ = 1;
    UnknownKeyPolicy unknown_policy_ = UnknownKeyPolicy::Reject;
    std::vector<SettingDefinition> definitions_{};
};

// Abstract secret storage interface so secret values are never persisted in plaintext.
class ISecretStore {
public:
    virtual ~ISecretStore() = default;
    [[nodiscard]] virtual Result<std::string> store_secret(std::string_view secret_id,
                                                           std::string_view plaintext) = 0;
    [[nodiscard]] virtual Result<std::string> load_secret(std::string_view secret_ref) const = 0;
};

// Abstract persistence store for Profile objects.
class ProfileStore {
public:
    virtual ~ProfileStore() = default;
    [[nodiscard]] virtual Result<Profile> load(std::string_view profile_id) const = 0;
    [[nodiscard]] virtual Status save(Profile& profile) = 0;
    [[nodiscard]] virtual Status remove(std::string_view profile_id) = 0;
    [[nodiscard]] virtual Result<std::vector<std::string>> list() const = 0;
};

struct ProvenanceEntry {
    std::string key{};
    SettingValue value{};
    SettingLayer source_layer = SettingLayer::BuiltIn;
};

// Immutable, lock-free snapshot published atomically by ProfileManager.
class ProfileSnapshot {
public:
    ProfileSnapshot(std::string active_profile_id,
                    std::uint64_t revision,
                    std::vector<ProvenanceEntry> entries) noexcept
        : active_profile_id_(std::move(active_profile_id)),
          revision_(revision),
          entries_(std::move(entries)) {}

    [[nodiscard]] std::string_view active_profile_id() const noexcept { return active_profile_id_; }
    [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }

    [[nodiscard]] const ProvenanceEntry* find_entry(std::string_view key) const noexcept {
        for (const auto& e : entries_) {
            if (e.key == key) {
                return &e;
            }
        }
        return nullptr;
    }

    [[nodiscard]] std::optional<SettingLayer> provenance(std::string_view key) const noexcept {
        if (const auto* e = find_entry(key)) {
            return e->source_layer;
        }
        return std::nullopt;
    }

    template <class T>
    [[nodiscard]] Result<T> get(Key<T> key) const {
        const auto* e = find_entry(key.name);
        if (e == nullptr) {
            return fail(ErrorCode::NotFound, "ProfileSnapshot::get", 0, std::string(key.name));
        }
        if constexpr (std::same_as<T, int>) {
            if (const auto* iv = std::get_if<std::int64_t>(&e->value)) {
                return static_cast<int>(*iv);
            }
        } else {
            if (const auto* p = std::get_if<T>(&e->value)) {
                return *p;
            }
        }
        return fail(ErrorCode::ValidationFailed,
                    "ProfileSnapshot::get",
                    0,
                    "Setting value type mismatch");
    }

    [[nodiscard]] std::span<const ProvenanceEntry> entries() const noexcept { return entries_; }

private:
    std::string active_profile_id_{};
    std::uint64_t revision_ = 0;
    std::vector<ProvenanceEntry> entries_{};
};

struct MigrationStep {
    std::uint32_t from_version = 1;
    std::uint32_t to_version = 2;
    std::move_only_function<Status(Profile&)> migrate{};
};

// Thread-safe profile manager with layered precedence, schema migration, and atomic snapshot publication.
class ProfileManager {
public:
    explicit ProfileManager(SettingsSchema schema,
                            std::shared_ptr<ProfileStore> store = nullptr,
                            std::shared_ptr<ISecretStore> secret_store = nullptr);

    void register_migration(MigrationStep step);

    void set_layer_values(SettingLayer layer,
                          std::vector<std::pair<std::string, SettingValue>> values);

    void set_runtime_override(std::string key, SettingValue value);
    void clear_runtime_overrides();

    // Atomically validates, migrates, and activates `profile`.
    // On failure, the previously active snapshot remains completely unchanged.
    [[nodiscard]] Result<SchemaValidationReport> activate_profile(Profile profile);

    // Loads a profile from the attached ProfileStore, migrates, validates, and activates it atomically.
    [[nodiscard]] Result<SchemaValidationReport> load_and_activate(std::string_view profile_id);

    [[nodiscard]] Status save_active_profile();

    [[nodiscard]] Result<Profile> clone_active_profile(std::string new_id,
                                                       std::string new_name) const;

    // Lock-free atomic snapshot read for concurrent readers.
    [[nodiscard]] std::shared_ptr<const ProfileSnapshot> snapshot() const noexcept {
        return active_snapshot_.load(std::memory_order_acquire);
    }

    [[nodiscard]] Result<Profile> active_profile() const;

private:
    [[nodiscard]] Status run_migrations_locked(Profile& profile);
    [[nodiscard]] std::shared_ptr<const ProfileSnapshot> build_snapshot_locked(
        const Profile& active) const;

    SettingsSchema schema_;
    std::shared_ptr<ProfileStore> store_;
    std::shared_ptr<ISecretStore> secret_store_;
    mutable std::mutex mutex_{};
    std::vector<MigrationStep> migrations_{};
    std::array<std::vector<std::pair<std::string, SettingValue>>, 8> layers_{};
    Profile active_profile_{};
    std::atomic<std::shared_ptr<const ProfileSnapshot>> active_snapshot_{};
};

} // namespace tessera::profile
