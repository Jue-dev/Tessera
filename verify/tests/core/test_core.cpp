#include <catch2/catch_test_macros.hpp>

#include <limits>
#include <string>

#include "tessera/core/core.hpp"
#include "tessera/diagnostics/diagnostics.hpp"

namespace {

enum class TestFlags : std::uint32_t {
    None = 0,
    Alpha = 1u << 0,
    Beta = 1u << 1,
    Gamma = 1u << 2,
};

} // namespace

TESSERA_ENABLE_ENUM_FLAGS(TestFlags);

TEST_CASE("Core checked_math detects overflow and underflow", "[core]") {
    using namespace tessera;

    constexpr auto max_u64 = (std::numeric_limits<std::uint64_t>::max)();
    REQUIRE(checked_add<std::uint64_t>(10, 20).value() == 30);
    REQUIRE_FALSE(checked_add<std::uint64_t>(max_u64, 1).has_value());
    REQUIRE(checked_add<std::uint64_t>(max_u64, 1).error().code == ErrorCode::AddressOverflow);

    REQUIRE(checked_sub<std::uint64_t>(50, 20).value() == 30);
    REQUIRE_FALSE(checked_sub<std::uint64_t>(10, 20).has_value());

    REQUIRE(checked_mul<std::uint64_t>(12, 12).value() == 144);
    REQUIRE_FALSE(checked_mul<std::uint64_t>(max_u64 / 2 + 2, 2).has_value());

    REQUIRE(checked_offset<std::uint64_t>(100, -40).value() == 60);
    REQUIRE_FALSE(checked_offset<std::uint64_t>(10, -20).has_value());
    REQUIRE_FALSE(
        checked_offset<std::uint64_t>(10, (std::numeric_limits<std::int64_t>::min)()).has_value());
}

TEST_CASE("Address, Rva, and AddressRange contracts", "[core]") {
    using namespace tessera;

    constexpr Address null_addr{};
    STATIC_REQUIRE(null_addr.is_null());
    STATIC_REQUIRE(!static_cast<bool>(null_addr));
    REQUIRE_FALSE(null_addr.offset(4).has_value());
    REQUIRE(null_addr.offset(4).error().code == ErrorCode::NullAddress);

    constexpr Address base{0x140000000ULL};
    auto off = base.offset(0x100);
    REQUIRE(off.has_value());
    REQUIRE(off->value() == 0x140000100ULL);

    // Offset resulting in 0 returns NullAddress
    REQUIRE_FALSE(Address{16}.offset(-16).has_value());
    REQUIRE(Address{16}.offset(-16).error().code == ErrorCode::NullAddress);

    const AddressRange mod_range{base, 0x2000};
    REQUIRE(mod_range.contains(base));
    REQUIRE(mod_range.contains(Address{0x140001FFFULL}));
    REQUIRE_FALSE(mod_range.contains(Address{0x140002000ULL}));

    auto rva = mod_range.to_rva(Address{0x140000500ULL});
    REQUIRE(rva.has_value());
    REQUIRE(rva->value() == 0x500u);

    auto roundtrip = mod_range.at_rva(*rva);
    REQUIRE(roundtrip.has_value());
    REQUIRE(*roundtrip == Address{0x140000500ULL});

    auto sub = mod_range.subrange(0x100, 0x200);
    REQUIRE(sub.has_value());
    REQUIRE(mod_range.contains_range(*sub));
    REQUIRE(mod_range.overlaps(*sub));
    REQUIRE_FALSE(mod_range.subrange(0x1F00, 0x200).has_value());
}

TEST_CASE("Result pipe operator and FunctionRef", "[core]") {
    using namespace tessera;

    Result<int> start = 10;
    auto chained = start | [](int x) -> Result<int> { return x * 2; } |
                   [](int x) -> int { return x + 5; };
    REQUIRE(chained.has_value());
    REQUIRE(*chained == 25);

    Result<int> failing = start | [](int) -> Result<int> {
        return fail(ErrorCode::NotFound, "step1");
    } | [](int x) -> Result<int> { return x + 100; };
    REQUIRE_FALSE(failing.has_value());
    REQUIRE(failing.error().code == ErrorCode::NotFound);

    int sum = 0;
    auto lambda = [&](int v) {
        sum += v;
        return sum;
    };
    FunctionRef<int(int)> fref{lambda};
    REQUIRE(fref.valid());
    REQUIRE(fref(7) == 7);
    REQUIRE(fref(8) == 15);

    const TestFlags flags = TestFlags::Alpha | TestFlags::Gamma;
    REQUIRE(has_flag(flags, TestFlags::Alpha));
    REQUIRE_FALSE(has_flag(flags, TestFlags::Beta));
    REQUIRE(any_flag(flags, TestFlags::Beta | TestFlags::Gamma));
}

TEST_CASE("Diagnostics formatting and observer notification", "[diagnostics]") {
    using namespace tessera;

    const Error err = make_error(ErrorCode::AccessDenied, "OpenProcess", 5, "permission denied");
    const std::string desc = diagnostics::describe(err);
    REQUIRE(desc.find("AccessDenied") != std::string::npos);
    REQUIRE(desc.find("OpenProcess") != std::string::npos);
    REQUIRE(desc.find("permission denied") != std::string::npos);

    REQUIRE(diagnostics::format_address(Address{0x1234ULL}, 4) == "0x00001234");
    REQUIRE(diagnostics::format_address(Address{0x140001000ULL}, 8) == "0x0000000140001000");

    struct CapturingObserver final : DiagnosticObserver {
        int count = 0;
        DiagnosticSeverity last_severity = DiagnosticSeverity::Info;
        void on_diagnostic(const DiagnosticEvent& ev) noexcept override {
            ++count;
            last_severity = ev.severity;
        }
    } obs;

    diagnostics::notify(&obs, DiagnosticSeverity::Warning, "Test", "warn message", err);
    REQUIRE(obs.count == 1);
    REQUIRE(obs.last_severity == DiagnosticSeverity::Warning);
}
