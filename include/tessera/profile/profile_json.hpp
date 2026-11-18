#pragma once

#include <filesystem>

#include "tessera/core/result.hpp"
#include "tessera/json/json.hpp"
#include "tessera/profile/profile.hpp"

namespace tessera::profile {

[[nodiscard]] Result<json::JsonValue> serialize_profile_to_json(
    const Profile& profile,
    const SettingsSchema* schema = nullptr,
    ISecretStore* secret_store = nullptr);

[[nodiscard]] Result<Profile> deserialize_profile_from_json(
    const json::JsonValue& root,
    const SettingsSchema* schema = nullptr,
    const ISecretStore* secret_store = nullptr);

// JSON-backed ProfileStore using AtomicFileWriter and optimistic revision checking.
class JsonProfileStore final : public ProfileStore {
public:
    explicit JsonProfileStore(std::filesystem::path directory,
                              const SettingsSchema* schema = nullptr,
                              ISecretStore* secret_store = nullptr) noexcept
        : directory_(std::move(directory)),
          schema_(schema),
          secret_store_(secret_store) {}

    [[nodiscard]] Result<Profile> load(std::string_view profile_id) const override;
    [[nodiscard]] Status save(Profile& profile) override;
    [[nodiscard]] Status remove(std::string_view profile_id) override;
    [[nodiscard]] Result<std::vector<std::string>> list() const override;

    [[nodiscard]] const std::filesystem::path& directory() const noexcept { return directory_; }

private:
    [[nodiscard]] std::filesystem::path path_for(std::string_view profile_id) const;

    std::filesystem::path directory_;
    const SettingsSchema* schema_ = nullptr;
    ISecretStore* secret_store_ = nullptr;
};

} // namespace tessera::profile
