#pragma once

#include <concepts>
#include <functional>
#include <limits>
#include <vector>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "tessera/core/error.hpp"
#include "tessera/core/result.hpp"
#include "tessera/json/json.hpp"

namespace tessera::json::detail {

template <class Range, class Converter>
[[nodiscard]] JsonValue::Array serialize_array(const Range& values, Converter&& converter) {
    JsonValue::Array result;
    if constexpr (requires { values.size(); }) {
        result.reserve(values.size());
    }
    for (const auto& value : values) {
        result.emplace_back(std::invoke(converter, value));
    }
    return result;
}

template <class T, class Converter>
[[nodiscard]] Result<std::vector<T>> parse_array(const JsonValue& value,
                                                 std::string_view operation,
                                                 std::string_view invalid_message,
                                                 Converter&& converter) {
    if (!value.is_array()) {
        return fail(ErrorCode::ParseError, operation, 0, std::string(invalid_message));
    }
    std::vector<T> result;
    result.reserve(value.as_array()->size());
    for (const auto& item : *value.as_array()) {
        auto converted = std::invoke(converter, item);
        if (!converted) {
            return fail(ErrorCode::ParseError, operation, 0, std::string(invalid_message));
        }
        result.emplace_back(std::move(*converted));
    }
    return result;
}

template <class Container, class Converter>
void append_array(const JsonValue& value, Container& destination, Converter&& converter) {
    if (!value.is_array()) {
        return;
    }
    for (const auto& item : *value.as_array()) {
        auto converted = std::invoke(converter, item);
        if (converted) {
            destination.emplace_back(std::move(*converted));
        }
    }
}

template <std::unsigned_integral T>
[[nodiscard]] Result<T> checked_unsigned(const JsonValue& value,
                                         std::string_view operation,
                                         std::string_view invalid_message) {
    const auto number = value.as_uint64();
    if (!number || *number > (std::numeric_limits<T>::max)()) {
        return fail(ErrorCode::ParseError, operation, 0, std::string(invalid_message));
    }
    return static_cast<T>(*number);
}

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
