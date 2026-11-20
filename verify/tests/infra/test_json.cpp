#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <thread>
#include <vector>

#include "tessera/filesystem/filesystem.hpp"
#include "tessera/json/json.hpp"
#include "tessera/logging/logging.hpp"
#include "tessera/profiling/profiling.hpp"
#include "tessera/reflection/reflection.hpp"
#include "tessera/utility/utility.hpp"

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

    // Reject duplicate keys by default
    JsonParseError jerr{};
    REQUIRE_FALSE(parse(R"({"a": 1, "a": 2})", {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::DuplicateKey);

    // Reject leading zeros
    REQUIRE_FALSE(parse(R"({"a": 01})", {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::InvalidNumber);

    // Reject trailing comma
    REQUIRE_FALSE(parse(R"([1, 2,])", {}, &jerr).has_value());

    // Reject unpaired UTF-16 surrogate
    REQUIRE_FALSE(parse(R"("\uD800")", {}, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::InvalidStringEscape);

    // Reject excessive nesting depth
    JsonParseOptions low_depth{.max_depth = 3};
    REQUIRE_FALSE(parse("[[[[]]]]", low_depth, &jerr).has_value());
    REQUIRE(jerr.code == JsonErrorCode::MaxDepthExceeded);
}

