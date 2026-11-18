#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "tessera/core/result.hpp"

namespace tessera::json {

enum class JsonType : std::uint8_t {
    Null,
    Bool,
    Int64,
    UInt64,
    Double,
    String,
    Array,
    Object,
};

enum class DuplicateKeyPolicy : std::uint8_t {
    Reject,
    Overwrite,
};

enum class JsonErrorCode : std::uint8_t {
    None,
    EmptyInput,
    InvalidUtf8,
    UnexpectedToken,
    UnexpectedEndOfInput,
    InvalidLiteral,
    InvalidNumber,
    NumberOverflow,
    InvalidStringEscape,
    UnescapedControlCharacter,
    UnterminatedString,
    DuplicateKey,
    MaxDepthExceeded,
    MaxSizeExceeded,
    TrailingContent,
};

struct JsonParseError {
    JsonErrorCode code = JsonErrorCode::None;
    std::size_t byte_offset = 0;
    std::size_t line = 1;
    std::size_t column = 1;
    std::string message{};
};

struct JsonParseOptions {
    std::size_t max_depth = 128;
    std::size_t max_bytes = 32ULL * 1024ULL * 1024ULL;
    DuplicateKeyPolicy duplicate_keys = DuplicateKeyPolicy::Reject;
};

struct JsonWriteOptions {
    bool pretty = true;
    std::size_t indent_spaces = 2;
};

class JsonValue {
public:
    using Array = std::vector<JsonValue>;
    using ObjectMember = std::pair<std::string, JsonValue>;
    using Object = std::vector<ObjectMember>;

    JsonValue() noexcept : storage_(nullptr) {}
    JsonValue(std::nullptr_t) noexcept : storage_(nullptr) {}
    JsonValue(bool b) noexcept : storage_(b) {}
    JsonValue(std::int64_t i) noexcept : storage_(i) {}
    JsonValue(int i) noexcept : storage_(static_cast<std::int64_t>(i)) {}
    JsonValue(std::uint64_t u) noexcept : storage_(u) {}
    JsonValue(double d) noexcept : storage_(d) {}
    JsonValue(std::string s) noexcept : storage_(std::move(s)) {}
    JsonValue(std::string_view sv) : storage_(std::string(sv)) {}
    JsonValue(const char* s) : storage_(std::string(s ? s : "")) {}
    JsonValue(Array arr) noexcept : storage_(std::move(arr)) {}
    JsonValue(Object obj) noexcept : storage_(std::move(obj)) {}

    [[nodiscard]] static JsonValue make_object() { return JsonValue{Object{}}; }
    [[nodiscard]] static JsonValue make_array() { return JsonValue{Array{}}; }

    [[nodiscard]] JsonType type() const noexcept {
        return static_cast<JsonType>(storage_.index());
    }

    [[nodiscard]] bool is_null() const noexcept { return type() == JsonType::Null; }
    [[nodiscard]] bool is_bool() const noexcept { return type() == JsonType::Bool; }
    [[nodiscard]] bool is_int64() const noexcept { return type() == JsonType::Int64; }
    [[nodiscard]] bool is_uint64() const noexcept { return type() == JsonType::UInt64; }
    [[nodiscard]] bool is_double() const noexcept { return type() == JsonType::Double; }
    [[nodiscard]] bool is_number() const noexcept {
        return is_int64() || is_uint64() || is_double();
    }
    [[nodiscard]] bool is_string() const noexcept { return type() == JsonType::String; }
    [[nodiscard]] bool is_array() const noexcept { return type() == JsonType::Array; }
    [[nodiscard]] bool is_object() const noexcept { return type() == JsonType::Object; }

    [[nodiscard]] std::optional<bool> as_bool() const noexcept {
        if (const auto* p = std::get_if<bool>(&storage_)) {
            return *p;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::int64_t> as_int64() const noexcept {
        if (const auto* p = std::get_if<std::int64_t>(&storage_)) {
            return *p;
        }
        if (const auto* u = std::get_if<std::uint64_t>(&storage_)) {
            if (*u <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
                return static_cast<std::int64_t>(*u);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::uint64_t> as_uint64() const noexcept {
        if (const auto* u = std::get_if<std::uint64_t>(&storage_)) {
            return *u;
        }
        if (const auto* i = std::get_if<std::int64_t>(&storage_)) {
            if (*i >= 0) {
                return static_cast<std::uint64_t>(*i);
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<double> as_double() const noexcept {
        if (const auto* d = std::get_if<double>(&storage_)) {
            return *d;
        }
        if (const auto* i = std::get_if<std::int64_t>(&storage_)) {
            return static_cast<double>(*i);
        }
        if (const auto* u = std::get_if<std::uint64_t>(&storage_)) {
            return static_cast<double>(*u);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::string_view> as_string() const noexcept {
        if (const auto* s = std::get_if<std::string>(&storage_)) {
            return std::string_view{*s};
        }
        return std::nullopt;
    }

    [[nodiscard]] const Array* as_array() const noexcept {
        return std::get_if<Array>(&storage_);
    }
    [[nodiscard]] Array* as_array() noexcept {
        return std::get_if<Array>(&storage_);
    }

    [[nodiscard]] const Object* as_object() const noexcept {
        return std::get_if<Object>(&storage_);
    }
    [[nodiscard]] Object* as_object() noexcept {
        return std::get_if<Object>(&storage_);
    }

    // Object helpers
    [[nodiscard]] const JsonValue* find(std::string_view key) const noexcept {
        const auto* obj = as_object();
        if (obj == nullptr) {
            return nullptr;
        }
        for (const auto& [k, v] : *obj) {
            if (k == key) {
                return &v;
            }
        }
        return nullptr;
    }

    [[nodiscard]] JsonValue* find(std::string_view key) noexcept {
        auto* obj = as_object();
        if (obj == nullptr) {
            return nullptr;
        }
        for (auto& [k, v] : *obj) {
            if (k == key) {
                return &v;
            }
        }
        return nullptr;
    }

    void set(std::string key, JsonValue value) {
        if (!is_object()) {
            storage_ = Object{};
        }
        auto& obj = std::get<Object>(storage_);
        for (auto& [k, v] : obj) {
            if (k == key) {
                v = std::move(value);
                return;
            }
        }
        obj.emplace_back(std::move(key), std::move(value));
    }

    void push_back(JsonValue value) {
        if (!is_array()) {
            storage_ = Array{};
        }
        std::get<Array>(storage_).push_back(std::move(value));
    }

    [[nodiscard]] friend bool operator==(const JsonValue& lhs, const JsonValue& rhs) noexcept = default;

private:
    std::variant<std::nullptr_t,
                 bool,
                 std::int64_t,
                 std::uint64_t,
                 double,
                 std::string,
                 Array,
                 Object>
        storage_;
};

[[nodiscard]] Result<JsonValue> parse(std::string_view input,
                                      const JsonParseOptions& options = {},
                                      JsonParseError* out_error = nullptr);

[[nodiscard]] Result<std::string> write(const JsonValue& value,
                                        const JsonWriteOptions& options = {});

} // namespace tessera::json
