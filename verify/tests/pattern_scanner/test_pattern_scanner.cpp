#include <catch2/catch_test_macros.hpp>

#include <array>
#include <stop_token>
#include <atomic>
#include <thread>

#include "FakeMemoryBackend.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/scanner/xref.hpp"

namespace {

struct PackedStruct {
    std::uint32_t a;
    std::uint32_t b;
};

struct PaddedStruct {
    std::uint8_t a;
    std::uint64_t b;
};

} // namespace

TEST_CASE("Pattern parsing, nibble wildcards, consteval literal, and PatternValue concept", "[pattern]") {
    using namespace tessera;
    using namespace tessera::literals;

    STATIC_REQUIRE(PatternValue<std::uint32_t>);
    STATIC_REQUIRE(PatternValue<PackedStruct>);
    STATIC_REQUIRE(!PatternValue<PaddedStruct>);

    constexpr Pattern lit = "48 8B 05 ?? ?? ?? ?? 4? ?F"_sig;
    STATIC_REQUIRE(lit.size() == 9);
    STATIC_REQUIRE(lit.anchor_index().has_value());

    constexpr Pattern trimmed = "?? ?? 48 8B 05 ?? ?? 90 ??"_sig;
    STATIC_REQUIRE(trimmed.leading_wildcards() == 2);
    STATIC_REQUIRE(trimmed.trailing_wildcards() == 1);
    STATIC_REQUIRE(trimmed.secondary_anchor_index().has_value());
    STATIC_REQUIRE(trimmed.secondary_anchor_index() != trimmed.anchor_index());

    const std::array<std::byte, 8> trimmed_sample{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B},
        std::byte{0x05}, std::byte{0x11}, std::byte{0x22}, std::byte{0x90}};
    std::size_t trimmed_match = 99;
    trimmed.search(trimmed_sample, trimmed_sample.size(), [&](std::size_t offset) {
        trimmed_match = offset;
        return false;
    });
    REQUIRE(trimmed_match == 0);

    const std::array<std::byte, 9> sample{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
        std::byte{0x4A}, std::byte{0xBF}};
    REQUIRE(lit.matches(sample));

    // All-wildcard pattern is rejected
    PatternError perr{};
    auto bad_wild = Pattern::parse("?? ? * **", &perr);
    REQUIRE_FALSE(bad_wild.has_value());
    REQUIRE(bad_wild.error().code == ErrorCode::InvalidPattern);

    // Odd-length hex token is rejected with position info
    auto bad_odd = Pattern::parse("48 8B 0", &perr);
    REQUIRE_FALSE(bad_odd.has_value());
    REQUIRE(perr.position == 6);

    // from_code
    const std::array<std::byte, 4> code_bytes{
        std::byte{0xE8}, std::byte{0x00}, std::byte{0x00}, std::byte{0x90}};
    auto code_pat = Pattern::from_code(code_bytes, "x??x");
    REQUIRE(code_pat.has_value());
    REQUIRE(code_pat->size() == 4);

    // UTF-16 pattern
    auto u16_pat = Pattern::from_utf16(u"AB");
    REQUIRE(u16_pat.has_value());
    REQUIRE(u16_pat->size() == 4);

    // ASCII text & raw bytes patterns
    auto ascii_pat = Pattern::from_text("TES");
    REQUIRE(ascii_pat.has_value());
    REQUIRE(ascii_pat->size() == 3);

    const std::array<std::byte, 3> raw_b{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
    auto bytes_pat = Pattern::from_bytes(raw_b);
    REQUIRE(bytes_pat.has_value());
    REQUIRE(bytes_pat->matches(raw_b));
}

TEST_CASE("Scanner chunk overlap, contiguous region merging, bad page skip, and xref", "[scanner]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    // Two contiguous 4 KiB regions: pattern spanning across the boundary at 0x20FFDE..0x210004
    backend->map_region(Address{0x200000}, 0x1000, MemoryProtection::ExecuteRead);
    backend->map_region(Address{0x201000}, 0x2000, MemoryProtection::ExecuteRead);

    const std::array<std::byte, 6> boundary_sig{
        std::byte{0x48}, std::byte{0x8D}, std::byte{0x0D},
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}};
    backend->poke_bytes(Address{0x200FFD}, boundary_sig);

    // Second match inside second chunk (chunk_size = 0x1000)
    backend->poke_bytes(Address{0x201800}, boundary_sig);

    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64);
    Scanner scanner{proc};

    ScanOptions opts{};
    opts.chunk_size = 0x1000;
    opts.filter.executable_only = true;

    const AddressRange scan_range{Address{0x200000}, 0x3000};
    constexpr Pattern sig = "48 8D 0D AA BB CC"_sig;

    auto res = scanner.scan(scan_range, sig, opts);
    REQUIRE(res.has_value());
    REQUIRE(res->hits.size() == 2);
    REQUIRE(res->hits[0] == Address{0x200FFD});
    REQUIRE(res->hits[1] == Address{0x201800});

    const std::array<Pattern, 2> batch_patterns{sig, "8D 0D AA"_sig};
    auto batch = scanner.scan_batch(scan_range, batch_patterns, opts);
    REQUIRE(batch.has_value());
    REQUIRE(batch->size() == 2);
    REQUIRE((*batch)[0].hits.size() == 2);
    REQUIRE((*batch)[1].hits.size() == 2);
    REQUIRE((*batch)[0].hits.front() == Address{0x200FFD});
    REQUIRE((*batch)[1].hits.front() == Address{0x200FFE});

    // find_first succeeds; find_unique returns Ambiguous when > 1 match exists
    REQUIRE(scanner.find_first(scan_range, sig, opts).value() == Address{0x200FFD});
    auto uniq = scanner.find_unique(scan_range, sig, opts);
    REQUIRE_FALSE(uniq.has_value());
    REQUIRE(uniq.error().code == ErrorCode::Ambiguous);

    // Cancellation via std::stop_source
    std::stop_source ssrc;
    ssrc.request_stop();
    opts.stop = ssrc.get_token();
    auto cancelled_res = scanner.scan(scan_range, sig, opts);
    REQUIRE(cancelled_res.has_value());
    REQUIRE(cancelled_res->cancelled);

    // Xref: direct E8 call to target 0x202000 placed at 0x200100 (disp32 = 0x202000 - (0x200100 + 5))
    const std::int32_t call_disp = 0x202000 - (0x200100 + 5);
    backend->poke_value<std::uint8_t>(Address{0x200100}, 0xE8u);
    backend->poke_value<std::int32_t>(Address{0x200101}, call_disp);

    auto calls = xref::find_calls(proc, scan_range, Address{0x202000});
    REQUIRE(calls.has_value());
    REQUIRE(calls->size() == 1);
    REQUIRE(calls->front() == Address{0x200100});

    // Xref: direct E9 jump to target 0x202000 placed at 0x200120
    const std::int32_t jmp_disp = 0x202000 - (0x200120 + 5);
    backend->poke_value<std::uint8_t>(Address{0x200120}, 0xE9u);
    backend->poke_value<std::int32_t>(Address{0x200121}, jmp_disp);

    auto jumps = xref::find_jumps(proc, scan_range, Address{0x202000});
    REQUIRE(jumps.has_value());
    REQUIRE(jumps->size() == 1);
    REQUIRE(jumps->front() == Address{0x200120});

    // Conditional near Jcc (0F 85 rel32) to the same target.
    const std::int32_t jcc_disp = 0x202000 - (0x200140 + 6);
    backend->poke_value<std::uint8_t>(Address{0x200140}, 0x0Fu);
    backend->poke_value<std::uint8_t>(Address{0x200141}, 0x85u);
    backend->poke_value<std::int32_t>(Address{0x200142}, jcc_disp);
    auto conditional = xref::find_conditional_branches(proc, scan_range, Address{0x202000});
    REQUIRE(conditional.has_value());
    REQUIRE(conditional->size() == 1);
    REQUIRE(conditional->front() == Address{0x200140});

    backend->poke_value<std::uint64_t>(Address{0x200600}, 0x202000ULL);
    // RIP-relative indirect CALL [rip+disp32] whose slot contains the target.
    const std::int32_t slot_disp = 0x200600 - (0x200180 + 6);
    backend->poke_value<std::uint8_t>(Address{0x200180}, 0xFFu);
    backend->poke_value<std::uint8_t>(Address{0x200181}, 0x15u);
    backend->poke_value<std::int32_t>(Address{0x200182}, slot_disp);
    auto indirect = xref::find_indirect_refs(proc, scan_range, Address{0x202000});
    REQUIRE(indirect.has_value());
    REQUIRE(indirect->size() == 1);
    REQUIRE(indirect->front() == Address{0x200180});
    const std::array<Address, 2> xref_targets{Address{0x202000}, Address{0x203000}};
    auto batched_refs = xref::find_pointer_refs_batch(proc, scan_range, xref_targets);
    REQUIRE(batched_refs.has_value());
    REQUIRE(batched_refs->size() == 2);
    REQUIRE((*batched_refs)[0].size() == 1);
    REQUIRE((*batched_refs)[0].front() == Address{0x200600});
    REQUIRE((*batched_refs)[1].empty());

    // Typed value scan via Pattern::from_value<uint32_t>
    backend->poke_value<std::uint32_t>(Address{0x200500}, 0xCAFEBABEu);
    ScanOptions val_opts{};
    val_opts.filter.executable_only = true;
    auto val_pat = Pattern::from_value<std::uint32_t>(0xCAFEBABEu);
    REQUIRE(val_pat.has_value());
    auto val_hits = scanner.scan(scan_range, *val_pat, val_opts);
    REQUIRE(val_hits.has_value());
    REQUIRE(val_hits->hits.size() == 1);
    REQUIRE(val_hits->hits.front() == Address{0x200500});

    // Xref: x86 pointer scan rejects > 4 GiB target with OutOfRange
    Process proc_x86 = FakeMemoryBackend::make_process(backend, Architecture::X86);
    auto bad_ptr_xref =
        xref::find_pointer_refs(proc_x86, scan_range, Address{0x100000000ULL});
    REQUIRE_FALSE(bad_ptr_xref.has_value());
    REQUIRE(bad_ptr_xref.error().code == ErrorCode::OutOfRange);
}

TEST_CASE("Scanner supports deterministic concurrent read-only scans", "[scanner][concurrency]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x720000}, 0x4000, MemoryProtection::ExecuteRead);
    constexpr std::array<std::byte, 4> signature{
        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    backend->poke_bytes(Address{0x720100}, signature);
    backend->poke_bytes(Address{0x721100}, signature);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    const Scanner scanner{process};
    const Pattern pattern = Pattern::from_bytes(signature).value();
    const AddressRange range{Address{0x720000}, 0x4000};

    std::atomic<int> successful_scans{0};
    std::array<std::jthread, 4> workers;
    for (auto& worker : workers) {
        worker = std::jthread([&] {
            const auto result = scanner.scan(range, pattern);
            if (result && result->hits.size() == 2) {
                successful_scans.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    REQUIRE(successful_scans.load(std::memory_order_relaxed) == 4);
}

TEST_CASE("Scanner reports query failures and rejects chunk overlap overflow", "[scanner][safety]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    Scanner scanner{process};
    const Pattern pattern = "AA BB"_sig;

    auto query_failure = scanner.scan(AddressRange{Address{0x700000}, 0x1000}, pattern);
    REQUIRE_FALSE(query_failure.has_value());

    ScanOptions oversized{};
    oversized.chunk_size = (std::numeric_limits<std::size_t>::max)();
    backend->map_region(Address{0x710000}, 0x1000, MemoryProtection::ExecuteRead);
    auto overflow = scanner.scan(AddressRange{Address{0x710000}, 0x1000}, pattern, oversized);
    REQUIRE_FALSE(overflow.has_value());
    REQUIRE(overflow.error().code == ErrorCode::OutOfRange);
}
