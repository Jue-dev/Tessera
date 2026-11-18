#pragma once

#include <cstdint>
#include <string>

#include "tessera/core/error.hpp"
#include "tessera/core/types.hpp"

namespace tessera::diagnostics {

[[nodiscard]] std::string format_native_error(std::uint32_t native_code);

[[nodiscard]] std::string describe(const Error& err);

[[nodiscard]] std::string format_address(Address addr, std::uint8_t pointer_size = 8);

[[nodiscard]] std::string capture_debug_stacktrace(std::size_t skip_frames = 1);

} // namespace tessera::diagnostics
