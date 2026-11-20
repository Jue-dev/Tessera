#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "tessera/json/json.hpp"

TEST_CASE("Strict RFC 8259 JSON parser and writer", "[json]") {
    using namespace tessera::json;

    const std::string_view valid_json = R"({
        "nullVal": null,
        "boolVal": true,
        "int64Val": -9223372036854775807,
        "uint64Val": 18446744073709551615,
        "doubleVal": 3.14159,
        "emoji": "\uD83D\uDE80",
        "arr": [1, 2, 3]
    })";

    auto parsed = parse(valid_json);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->is_object());
    REQUIRE(parsed->find("nullVal")->is_null());
    REQUIRE(parsed->find("boolVal")->as_bool().value() == true);
    REQUIRE(parsed->find("int64Val")->as_int64().value() == -9223372036854775807LL);
    REQUIRE(parsed->find("uint64Val")->as_uint64().value() == 18446744073709551615ULL);
    REQUIRE(parsed->find("emoji")->as_string().value() == "\xF0\x9F\x9A\x80");

    auto written = write(*parsed);
    REQUIRE(written.has_value());
    auto reparsed = parse(*written);
    REQUIRE(reparsed.has_value());
    REQUIRE(*reparsed == *parsed);

    JsonParseError jerr{};
    REQUIRE_FALSE(parse(R"({"a": 1, "a": 2})", {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::DuplicateKey);

    REQUIRE_FALSE(parse(R"({"a": 01})", {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::InvalidNumber);

    REQUIRE_FALSE(parse(R"([1, 2,])", {}, &jerr).has_value());
    REQUIRE_FALSE(parse(R"("\uD800")", {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::InvalidStringEscape);

    JsonParseOptions low_depth{.max_depth = 3};
    REQUIRE_FALSE(parse("[[[[]]]]", low_depth, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::MaxDepthExceeded);

    JsonParseOptions tiny_input{.max_bytes = 2};
    REQUIRE_FALSE(parse("null", tiny_input, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::MaxSizeExceeded);

    const char invalid_byte[] = {static_cast<char>(0xFF)};
    REQUIRE_FALSE(parse(std::string_view{invalid_byte, sizeof(invalid_byte)}, {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::InvalidUtf8);
}

TEST_CASE("JSON parser rejects malformed encodings, escapes, and trailing data", "[json][boundary]") {
    using namespace tessera::json;

    JsonParseError error{};
    REQUIRE_FALSE(parse("").has_value());
    REQUIRE_FALSE(parse("   \t\r\n").has_value());
    REQUIRE_FALSE(parse("true false", {}, &error).has_value());
    REQUIRE(error.code == JsonErrorCode::TrailingContent);
    REQUIRE_FALSE(parse(R"({"value": 1} garbage)", {}, &error).has_value());
    REQUIRE(error.code == JsonErrorCode::TrailingContent);

    const std::string overlong = std::string{"\""} + "\xC0\xAF" + "\"";
    const std::string encoded_surrogate = std::string{"\""} + "\xED\xA0\x80" + "\"";
    const std::string above_unicode_max = std::string{"\""} + "\xF4\x90\x80\x80" + "\"";
    const std::string truncated_utf8 = std::string{"\""} + "\xE2\x82" + "\"";
    for (const auto& malformed : {overlong, encoded_surrogate, above_unicode_max, truncated_utf8}) {
        REQUIRE_FALSE(parse(malformed, {}, &error).has_value());
        REQUIRE(error.code == JsonErrorCode::InvalidUtf8);
    }

    for (const auto malformed_escape : {
             R"("\x")", R"("\u12")", R"("\uZZZZ")", R"("\uDC00")", R"("\uD800x")"}) {
        REQUIRE_FALSE(parse(malformed_escape, {}, &error).has_value());
        REQUIRE(error.code == JsonErrorCode::InvalidStringEscape);
    }

    const std::string unescaped_newline = "\"first\nsecond\"";
    REQUIRE_FALSE(parse(unescaped_newline, {}, &error).has_value());
    REQUIRE(error.code == JsonErrorCode::UnescapedControlCharacter);
}

TEST_CASE("JSON numeric boundaries and overflow are explicit", "[json][numbers][boundary]") {
    using namespace tessera::json;

    auto signed_min = parse("-9223372036854775808");
    auto signed_max = parse("9223372036854775807");
    auto first_unsigned = parse("9223372036854775808");
    auto unsigned_max = parse("18446744073709551615");
    auto maximum_double = parse("1.7976931348623157e308");
    auto minimum_normal_double = parse("2.2250738585072014e-308");
    REQUIRE(signed_min.has_value());
    REQUIRE(signed_min->as_int64().value() == (std::numeric_limits<std::int64_t>::min)());
    REQUIRE(signed_max.has_value());
    REQUIRE(signed_max->as_int64().value() == (std::numeric_limits<std::int64_t>::max)());
    REQUIRE(first_unsigned.has_value());
    REQUIRE(first_unsigned->as_uint64().value() == 9223372036854775808ULL);
    REQUIRE(unsigned_max.has_value());
    REQUIRE(unsigned_max->as_uint64().value() == (std::numeric_limits<std::uint64_t>::max)());
    REQUIRE(maximum_double.has_value());
    REQUIRE(maximum_double->as_double().value() == (std::numeric_limits<double>::max)());
    REQUIRE(minimum_normal_double.has_value());
    REQUIRE(minimum_normal_double->as_double().value() > 0.0);

    JsonParseError error{};
    REQUIRE_FALSE(parse("18446744073709551616", {}, &error).has_value());
    REQUIRE(error.code == JsonErrorCode::NumberOverflow);
    REQUIRE_FALSE(parse("-9223372036854775809", {}, &error).has_value());
    REQUIRE_FALSE(parse("1e309", {}, &error).has_value());
}

TEST_CASE("JSON nested round trips preserve the complete value tree", "[json][roundtrip]") {
    using namespace tessera::json;

    JsonValue nested = JsonValue::make_object();
    nested.set("emptyArray", JsonValue::make_array());
    nested.set("emptyObject", JsonValue::make_object());
    for (std::int64_t index = 0; index < 24; ++index) {
        JsonValue layer = JsonValue::make_object();
        layer.set("index", JsonValue{index});
        JsonValue array = JsonValue::make_array();
        array.push_back(std::move(nested));
        array.push_back(JsonValue{index});
        layer.set("children", std::move(array));
        nested = std::move(layer);
    }

    JsonParseOptions options{.max_depth = 128};
    auto serialized = write(nested);
    REQUIRE(serialized.has_value());
    auto parsed = parse(*serialized, options);
    REQUIRE(parsed.has_value());
    REQUIRE(*parsed == nested);

    std::string deep(16, '[');
    deep += "0";
    deep.append(16, ']');
    REQUIRE(parse(deep, options).has_value());
    JsonParseOptions shallow{.max_depth = 8};
    JsonParseError error{};
    REQUIRE_FALSE(parse(deep, shallow, &error).has_value());
    REQUIRE(error.code == JsonErrorCode::MaxDepthExceeded);
}
