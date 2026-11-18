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

TEST_CASE("Utility hex, encoding, and SHA-256", "[utility]") {
    using namespace tessera;

    // SHA-256 of "abc"
    const std::string_view abc = "abc";
    const auto hash_hex =
        utility::sha256_hex(std::as_bytes(std::span<const char>(abc.data(), abc.size())));
    REQUIRE(hash_hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Hex encode & strict decode
    auto decoded = hex::decode("48 8B 05");
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->size() == 3);
    REQUIRE(hex::encode(*decoded) == "488B05");

    hex::HexDecodeError hex_err{};
    REQUIRE_FALSE(hex::decode("48 ZZ", &hex_err).has_value());
    REQUIRE(hex_err.position == 3);

    // Strict UTF-8 <-> UTF-16 conversion
    const std::string_view utf8_sample = "Merhaba \xF0\x9F\x9A\x80"; // "Merhaba 🚀"
    auto u16 = encoding::utf8_to_utf16(utf8_sample);
    REQUIRE(u16.has_value());
    auto u8_back = encoding::utf16_to_utf8(*u16);
    REQUIRE(u8_back.has_value());
    REQUIRE(*u8_back == utf8_sample);

    // Invalid UTF-8 (overlong / lone continuation byte) is rejected
    const std::string_view bad_utf8 = "\xC0\xAF";
    REQUIRE_FALSE(encoding::is_valid_utf8(bad_utf8));
    REQUIRE_FALSE(encoding::utf8_to_utf16(bad_utf8).has_value());

    // ScopeGuard execution and dismiss()
    int guard_counter = 0;
    {
        auto g1 = utility::make_scope_guard([&]() noexcept { ++guard_counter; });
        auto g2 = utility::make_scope_guard([&]() noexcept { ++guard_counter; });
        g2.dismiss();
    }
    REQUIRE(guard_counter == 1);

    // Little-endian read/write helpers
    std::array<std::byte, 4> le_buf{};
    utility::write_le<std::uint32_t>(0x11223344u, le_buf);
    REQUIRE(utility::read_le<std::uint32_t>(le_buf) == 0x11223344u);
}

TEST_CASE("AtomicFileWriter and FileLock", "[filesystem]") {
    using namespace tessera;

    const auto temp_dir = std::filesystem::temp_directory_path() / "tessera_fs_test";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    const auto file_path = temp_dir / "config.json";
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(file_path, "{\"ok\": true}").has_value());

    // Overwrite with backup
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(
                file_path, "{\"ok\": false}", {.create_backup = true, .write_through = true})
                .has_value());

    auto content = filesystem::read_file_utf8(file_path);
    REQUIRE(content.has_value());
    REQUIRE(*content == "{\"ok\": false}");

    // Exclusive FileLock prevents second concurrent exclusive lock on the same file
    const auto lock_path = temp_dir / "test.lock";
    auto lock1 = filesystem::FileLock::acquire(lock_path, true, true);
    REQUIRE(lock1.has_value());
    auto lock2 = filesystem::FileLock::acquire(lock_path, true, true);
    REQUIRE_FALSE(lock2.has_value());
    REQUIRE(lock2.error().code == ErrorCode::Conflict);
    lock1->release();
    auto lock3 = filesystem::FileLock::acquire(lock_path, true, true);
    REQUIRE(lock3.has_value());
    lock3->release();

    std::filesystem::remove_all(temp_dir, ec);
}

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

TEST_CASE("Logging, Profiling, and Reflection thread-safety", "[logging][profiling][reflection]") {
    using namespace tessera;

    auto mem_sink = std::make_shared<logging::MemorySink>();
    auto logger = std::make_shared<logging::Logger>("Scanner", logging::LogLevel::Info);
    logger->add_sink(mem_sink);

    logger->debug("Should be filtered out: {}", 123);
    logger->info("Scan started: module={}", "sample.exe");
    REQUIRE(mem_sink->records().size() == 1);
    REQUIRE(mem_sink->records()[0].message == "Scan started: module=sample.exe");

    logging::LoggerDiagnosticObserver obs{logger};
    diagnostics::notify(&obs, DiagnosticSeverity::Warning, "Scanner", "Region skipped");
    REQUIRE(mem_sink->records().size() == 2);

    // Profiling ScopeTimer
    std::chrono::nanoseconds recorded_ns{0};
    {
        profiling::ScopeTimer timer(
            "op", [&](std::string_view, std::chrono::nanoseconds d) { recorded_ns = d; });
    }
    REQUIRE(recorded_ns.count() >= 0);

    // Reflection TypeRegistry concurrent registration
    reflection::TypeRegistry reg{};
    struct DummyVec3 {
        float x, y, z;
    };
    auto info = reflection::TypeBuilder<DummyVec3>("tessera::DummyVec3")
                    .member("x", reflection::TypeId::from_name("float"), 0, 4)
                    .member("y", reflection::TypeId::from_name("float"), 4, 4)
                    .member("z", reflection::TypeId::from_name("float"), 8, 4)
                    .build();
    REQUIRE(reg.register_type(info).has_value());
    // Duplicate registration returns Conflict
    REQUIRE(reg.register_type(info).error().code == ErrorCode::Conflict);

    auto looked_up = reg.find_by_name("tessera::DummyVec3");
    REQUIRE(looked_up.has_value());
    REQUIRE(looked_up->members.size() == 3);
}
