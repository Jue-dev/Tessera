#pragma once

#include <cstdint>
#include <string_view>

#define TESSERA_VERSION_MAJOR 0
#define TESSERA_VERSION_MINOR 1
#define TESSERA_VERSION_PATCH 0

namespace tessera {

struct Version {
    std::uint32_t major = TESSERA_VERSION_MAJOR;
    std::uint32_t minor = TESSERA_VERSION_MINOR;
    std::uint32_t patch = TESSERA_VERSION_PATCH;

    [[nodiscard]] constexpr auto operator<=>(const Version&) const noexcept = default;
};

[[nodiscard]] inline constexpr Version version() noexcept {
    return Version{};
}

[[nodiscard]] inline constexpr std::string_view version_string() noexcept {
    return "0.1.0";
}

} // namespace tessera
