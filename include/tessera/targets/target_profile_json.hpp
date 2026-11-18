#pragma once

#include <filesystem>

#include "tessera/core/result.hpp"
#include "tessera/json/json.hpp"
#include "tessera/targets/target_profile.hpp"

namespace tessera::targets {

[[nodiscard]] Result<json::JsonValue> serialize_target_profile_to_json(
    const TargetProfile& profile);

[[nodiscard]] Result<TargetProfile> deserialize_target_profile_from_json(
    const json::JsonValue& root);

// JSON-backed TargetProfileStore with AtomicFileWriter and optimistic revision checking.
class JsonTargetProfileStore final : public TargetProfileStore {
public:
    explicit JsonTargetProfileStore(std::filesystem::path directory) noexcept
        : directory_(std::move(directory)) {}

    [[nodiscard]] Result<TargetProfile> load(std::string_view application_id) const override;
    [[nodiscard]] Status save(TargetProfile& profile) override;
    [[nodiscard]] Result<std::vector<std::string>> list() const override;

    [[nodiscard]] const std::filesystem::path& directory() const noexcept { return directory_; }

private:
    [[nodiscard]] std::filesystem::path path_for(std::string_view application_id) const;

    std::filesystem::path directory_;
};

} // namespace tessera::targets
