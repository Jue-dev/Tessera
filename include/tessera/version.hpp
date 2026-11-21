#pragma once

#include <cstdint>
#include <string_view>

#define TESSERA_VERSION_MAJOR 0
#define TESSERA_VERSION_MINOR 1
#define TESSERA_VERSION_PATCH 0

#if defined(TESSERA_CMAKE_VERSION_MAJOR) && defined(TESSERA_CMAKE_VERSION_MINOR) && \
    defined(TESSERA_CMAKE_VERSION_PATCH)
static_assert(TESSERA_VERSION_MAJOR == TESSERA_CMAKE_VERSION_MAJOR);
static_assert(TESSERA_VERSION_MINOR == TESSERA_CMAKE_VERSION_MINOR);
static_assert(TESSERA_VERSION_PATCH == TESSERA_CMAKE_VERSION_PATCH);
#endif

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
