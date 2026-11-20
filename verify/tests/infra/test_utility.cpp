#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "tessera/utility/utility.hpp"

TEST_CASE("Utility hex, encoding, and SHA-256", "[utility]") {
    using namespace tessera;

    const std::string_view abc = "abc";
    const auto hash_hex =
        utility::sha256_hex(std::as_bytes(std::span<const char>(abc.data(), abc.size())));
    REQUIRE(hash_hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    auto decoded = hex::decode("48 8B 05");
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->size() == 3);
    REQUIRE(hex::encode(*decoded) == "488B05");

    hex::HexDecodeError hex_err{};
    REQUIRE_FALSE(hex::decode("48 ZZ", &hex_err).has_value());
    REQUIRE(hex_err.position == 3);

    const std::string_view utf8_sample = "Merhaba \xF0\x9F\x9A\x80";
    auto u16 = encoding::utf8_to_utf16(utf8_sample);
    REQUIRE(u16.has_value());
    auto u8_back = encoding::utf16_to_utf8(*u16);
    REQUIRE(u8_back.has_value());
    REQUIRE(*u8_back == utf8_sample);

    const std::string_view bad_utf8 = "\xC0\xAF";
    REQUIRE_FALSE(encoding::is_valid_utf8(bad_utf8));
    REQUIRE_FALSE(encoding::utf8_to_utf16(bad_utf8).has_value());

    int guard_counter = 0;
    {
        auto g1 = utility::make_scope_guard([&]() noexcept { ++guard_counter; });
        auto g2 = utility::make_scope_guard([&]() noexcept { ++guard_counter; });
        g2.dismiss();
    }
    REQUIRE(guard_counter == 1);

    std::array<std::byte, 4> le_buf{};
    utility::write_le<std::uint32_t>(0x11223344u, le_buf);
    REQUIRE(utility::read_le<std::uint32_t>(le_buf) == 0x11223344u);
}

TEST_CASE("Utility helpers cover empty input and malformed hex boundaries", "[utility][boundary]") {
    using namespace tessera;

    auto empty_hex = hex::decode("");
    REQUIRE(empty_hex.has_value());
    REQUIRE(empty_hex->empty());
    REQUIRE(hex::encode(*empty_hex).empty());

    hex::HexDecodeError error{};
    REQUIRE_FALSE(hex::decode("A", &error).has_value());
    REQUIRE(error.position == 0);
    REQUIRE_FALSE(hex::decode("0G", &error).has_value());
    REQUIRE(error.position == 1);
    REQUIRE_FALSE(hex::decode("0x 1", &error).has_value());

    auto empty_number = hex::parse_u64("");
    REQUIRE_FALSE(empty_number.has_value());
    auto maximum = hex::parse_u64("0xFFFFFFFFFFFFFFFF");
    REQUIRE(maximum.has_value());
    REQUIRE(*maximum == (std::numeric_limits<std::uint64_t>::max)());
    REQUIRE_FALSE(hex::parse_u64("10000000000000000").has_value());
    REQUIRE(hex::format_u64(0) == "0x0");
    REQUIRE(hex::format_u64((std::numeric_limits<std::uint64_t>::max)()) == "0xFFFFFFFFFFFFFFFF");

    const std::span<const std::byte> no_bytes{};
    REQUIRE(utility::sha256_hex(no_bytes) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    REQUIRE(encoding::is_valid_utf8(""));
    REQUIRE(encoding::is_valid_utf16(u""));
    auto empty_utf16 = encoding::utf8_to_utf16("");
    REQUIRE(empty_utf16.has_value());
    REQUIRE(empty_utf16->empty());
    auto empty_utf8 = encoding::utf16_to_utf8(u"");
    REQUIRE(empty_utf8.has_value());
    REQUIRE(empty_utf8->empty());
    const std::u16string lone_surrogate(1, static_cast<char16_t>(0xD800));
    REQUIRE_FALSE(encoding::is_valid_utf16(lone_surrogate));
    REQUIRE_FALSE(encoding::utf16_to_utf8(lone_surrogate).has_value());

    REQUIRE(utility::trim("").empty());
    REQUIRE(utility::trim(" \t\r\n").empty());
    REQUIRE(utility::ascii_to_lower("TeSsErA") == "tessera");
    REQUIRE(utility::ascii_to_upper("tessera") == "TESSERA");
    REQUIRE(utility::ascii_iequals("Tessera", "tESSERA"));
    REQUIRE(utility::ascii_icontains("A Tessera SDK", "tessera"));
    REQUIRE(utility::split("", ',').size() == 1);
    REQUIRE(utility::split("", ',', true).empty());
    const auto parts = utility::split("one,,three,", ',', true);
    REQUIRE(parts.size() == 2);
    REQUIRE(parts[0] == "one");
    REQUIRE(parts[1] == "three");

    std::array<std::byte, 8> wide_le{};
    utility::write_le<std::uint64_t>(0x0123456789ABCDEFULL, wide_le);
    REQUIRE(utility::read_le<std::uint64_t>(wide_le) == 0x0123456789ABCDEFULL);

    auto empty_path = utility::normalize_path(std::filesystem::path{});
    REQUIRE_FALSE(empty_path.has_value());
    REQUIRE(empty_path.error().code == ErrorCode::InvalidArgument);
    const auto root = std::filesystem::temp_directory_path() / "tessera_path_boundary";
    auto normalized = utility::normalize_path(root / "one" / ".." / "two");
    REQUIRE(normalized.has_value());
    REQUIRE(*normalized == (std::filesystem::absolute(root / "two")).lexically_normal());
    auto empty_app = utility::resolve_storage_directory("", utility::PathScope::Custom, root);
    REQUIRE_FALSE(empty_app.has_value());
    REQUIRE(empty_app.error().code == ErrorCode::InvalidArgument);
    auto empty_custom_root = utility::resolve_storage_directory("app", utility::PathScope::Custom);
    REQUIRE_FALSE(empty_custom_root.has_value());
    REQUIRE(empty_custom_root.error().code == ErrorCode::InvalidArgument);
    auto storage = utility::resolve_storage_directory("app", utility::PathScope::Custom, root);
    REQUIRE(storage.has_value());
    REQUIRE(*storage == (std::filesystem::absolute(root / "app")).lexically_normal());
}

TEST_CASE("ScopeGuard runs on early return and exception unwinding, and transfers ownership", "[utility][scope_guard]") {
    using namespace tessera::utility;

    int calls = 0;
    const auto early_return = [&]() {
        auto guard = make_scope_guard([&]() noexcept { ++calls; });
        return 42;
    };
    REQUIRE(early_return() == 42);
    REQUIRE(calls == 1);

    try {
        auto guard = make_scope_guard([&]() noexcept { ++calls; });
        throw std::runtime_error("scope exit");
    } catch (const std::runtime_error&) {
    }
    REQUIRE(calls == 2);

    {
        auto original = make_scope_guard([&]() noexcept { ++calls; });
        auto moved = std::move(original);
        (void)moved;
    }
    REQUIRE(calls == 3);

    {
        auto dismissed = make_scope_guard([&]() noexcept { ++calls; });
        dismissed.dismiss();
    }
    REQUIRE(calls == 3);
}
