#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "tessera/core/error.hpp"
#include "tessera/core/result.hpp"
#include "tessera/json/json.hpp"

namespace tessera::json::detail {

// Shared field readers for the profile JSON codecs. The caller owns the field
// schema and diagnostics; this layer only centralizes lookup and conversion.
template <class T, class Getter>
[[nodiscard]] std::optional<T> optional_field(const JsonValue& object,
                                              std::string_view name,
                                              Getter&& getter) {
    if (!object.is_object()) {
        return std::nullopt;
    }
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return std::nullopt;
    }
    return std::invoke(std::forward<Getter>(getter), *field);
}

template <class T, class Getter>
[[nodiscard]] Result<T> required_field(const JsonValue& object,
                                       std::string_view name,
                                       std::string_view operation,
                                       std::string_view missing_message,
                                       std::string_view invalid_message,
                                       Getter&& getter) {
    const JsonValue* field = object.is_object() ? object.find(name) : nullptr;
    if (field == nullptr) {
        return fail(ErrorCode::ParseError, operation, 0, std::string(missing_message));
    }

    auto converted = std::invoke(std::forward<Getter>(getter), *field);
    if (!converted.has_value()) {
        return fail(ErrorCode::ParseError, operation, 0, std::string(invalid_message));
    }
    return std::move(*converted);
}

} // namespace tessera::json::detail
