#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

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

