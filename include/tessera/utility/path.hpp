#pragma once

#include <filesystem>
#include <string_view>

#include "tessera/core/result.hpp"

namespace tessera::utility {

enum class PathScope : std::uint8_t {
    User,
    Machine,
    Custom,
};

[[nodiscard]] Result<std::filesystem::path> normalize_path(const std::filesystem::path& p);

[[nodiscard]] Result<std::filesystem::path> resolve_storage_directory(
    std::string_view app_id,
    PathScope scope,
    const std::filesystem::path& custom_root = {});

} // namespace tessera::utility
