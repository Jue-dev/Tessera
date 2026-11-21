#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>
#include <stop_token>
#include <atomic>
#include <thread>

#include "FakeMemoryBackend.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/scanner/xref.hpp"
#include "pattern/pattern_simd.hpp"

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

    constexpr Pattern exact = "48 8B 05 90"_sig;
    STATIC_REQUIRE(exact.is_exact());
    STATIC_REQUIRE(exact.is_byte_mask_only());
    STATIC_REQUIRE(!exact.is_nibble_masked());

    constexpr Pattern byte_masked = "48 ?? 05"_sig;
    STATIC_REQUIRE(!byte_masked.is_exact());
    STATIC_REQUIRE(byte_masked.is_byte_mask_only());
    STATIC_REQUIRE(!byte_masked.is_nibble_masked());

    constexpr Pattern nibble_masked = "4? 8B ?5"_sig;
    STATIC_REQUIRE(!nibble_masked.is_exact());
    STATIC_REQUIRE(!nibble_masked.is_byte_mask_only());
    STATIC_REQUIRE(nibble_masked.is_nibble_masked());

    constexpr Pattern trimmed = "?? ?? 48 8B 05 ?? ?? 90 ??"_sig;
    STATIC_REQUIRE(trimmed.leading_wildcards() == 2);
    STATIC_REQUIRE(trimmed.trailing_wildcards() == 1);
    STATIC_REQUIRE(trimmed.secondary_anchor_index().has_value());
    STATIC_REQUIRE(trimmed.secondary_anchor_index() != trimmed.anchor_index());

    const std::array<std::byte, 9> trimmed_sample{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B},
        std::byte{0x05}, std::byte{0x11}, std::byte{0x22}, std::byte{0x90},
        std::byte{0x7F}};
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

TEST_CASE("Pattern SIMD dispatch matches scalar results for overlapping signatures", "[pattern][simd]") {
    using namespace tessera;
    using namespace tessera::literals;

    std::array<std::byte, 256> data{};
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 37u + 11u) & 0xFFu);
    }
    constexpr Pattern pattern = "AA BB ?? 4? ?F 90"_sig;
    const std::array<std::size_t, 6> offsets{0, 15, 32, 63, 127, 250};
    for (const std::size_t offset : offsets) {
        data[offset] = std::byte{0xAA};
        data[offset + 1] = std::byte{0xBB};
        data[offset + 2] = std::byte{0x12};
        data[offset + 3] = std::byte{0x4C};
        data[offset + 4] = std::byte{0x2F};
        data[offset + 5] = std::byte{0x90};
    }

    std::vector<std::size_t> expected;
    for (std::size_t offset = 0; offset + pattern.size() <= data.size(); ++offset) {
        if (pattern.matches(std::span<const std::byte>{data}.subspan(offset))) {
            expected.push_back(offset);
        }
    }
    std::vector<std::size_t> actual;
    pattern.search(data, data.size(), [&](std::size_t offset) {
        actual.push_back(offset);
        return true;
    });
    REQUIRE(actual == expected);
    for (const std::size_t offset : offsets) {
        REQUIRE(std::find(actual.begin(), actual.end(), offset) != actual.end());
    }
}

TEST_CASE("SSE2 and AVX2 dual-anchor masks match scalar candidate filtering",
          "[pattern][simd][parity]") {
    using namespace tessera::pattern::detail;

    std::array<std::byte, 128> data{};
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 53u + 17u) & 0xFFu);
    }
    constexpr std::size_t primary = 2;
    constexpr std::size_t secondary = 7;
    constexpr std::byte primary_value{0x48};
    constexpr std::byte secondary_value{0x8B};
    constexpr std::array<std::size_t, 5> block_offsets{0, 15, 31, 32, 64};

    for (const std::size_t offset : block_offsets) {
        for (std::size_t lane = 0; lane < 32; ++lane) {
            if (((lane + offset) % 5u) == 0u) {
                data[offset + lane + primary] = primary_value;
            }
            if (((lane + offset) % 7u) == 0u) {
                data[offset + lane + secondary] = secondary_value;
            }
        }

        std::uint32_t expected_sse = 0;
        for (std::size_t lane = 0; lane < 16; ++lane) {
            if (data[offset + lane + primary] == primary_value &&
                data[offset + lane + secondary] == secondary_value) {
                expected_sse |= (std::uint32_t{1} << lane);
            }
        }
        std::uint32_t expected_avx = 0;
        for (std::size_t lane = 0; lane < 32; ++lane) {
            if (data[offset + lane + primary] == primary_value &&
                data[offset + lane + secondary] == secondary_value) {
                expected_avx |= (std::uint32_t{1} << lane);
            }
        }

        if (cpu_supports_sse2()) {
            REQUIRE(dual_anchor_mask_sse2(
                        data.data(), offset, primary, primary_value, secondary, secondary_value) ==
                    expected_sse);
        }
        if (cpu_supports_avx2()) {
            REQUIRE(dual_anchor_mask_avx2(
                        data.data(), offset, primary, primary_value, secondary, secondary_value) ==
                    expected_avx);
        }
    }
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

    ScanOptions quota_options{};
    quota_options.chunk_size = opts.chunk_size;
    quota_options.filter.executable_only = true;
    quota_options.max_results = 1;
    auto quota_batch = scanner.scan_batch(scan_range, batch_patterns, quota_options);
    REQUIRE(quota_batch.has_value());
    REQUIRE((*quota_batch)[0].hits.size() == 1);
    REQUIRE((*quota_batch)[1].hits.size() == 1);
    REQUIRE((*quota_batch)[0].truncated);
    REQUIRE((*quota_batch)[1].truncated);

    ScanWorkspace workspace;
    workspace.reserve(opts.chunk_size + sig.size() - 1);
    auto workspace_batch = scanner.scan_batch(scan_range, batch_patterns, opts, workspace);
    REQUIRE(workspace_batch.has_value());
    REQUIRE(workspace_batch->size() == 2);
    auto workspace_scan = scanner.scan(scan_range, sig, opts, workspace);
    REQUIRE(workspace_scan.has_value());
    REQUIRE(workspace_scan->hits.size() == 2);
    const std::size_t workspace_capacity = workspace.capacity();
    auto workspace_scan_again = scanner.scan(scan_range, sig, opts, workspace);
    REQUIRE(workspace_scan_again.has_value());
    REQUIRE(workspace.capacity() == workspace_capacity);

    std::vector<Address> streamed_hits;
    auto streamed = scanner.scan_streaming(
        scan_range, sig, opts,
        [&](Address address) {
            streamed_hits.push_back(address);
            return false;
        },
        &workspace);
    REQUIRE(streamed.has_value());
    REQUIRE(streamed->hits.empty());
    REQUIRE(streamed->cancelled);
    REQUIRE(streamed_hits.size() == 1);
    REQUIRE(streamed_hits.front() == Address{0x200FFD});
    REQUIRE(workspace.capacity() == workspace_capacity);

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

TEST_CASE("Scanner exposes strict and best-effort partial-read policies", "[scanner][read-policy]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& region = backend->map_region(
        Address{0x730000}, 0x1000, MemoryProtection::ExecuteRead);
    region.readable_prefix_limit = 0x800;
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    Scanner scanner{process};
    constexpr Pattern pattern = "90"_sig;
    const AddressRange range{Address{0x730000}, 0x1000};

    auto best_effort = scanner.scan(range, pattern);
    REQUIRE(best_effort.has_value());
    REQUIRE(best_effort->stats.read_errors == 1);

    auto strict = scanner.scan(range, pattern, ScanOptions{}, ScanReadPolicy::Strict);
    REQUIRE_FALSE(strict.has_value());
    REQUIRE(strict.error().code == ErrorCode::PartialTransfer);
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

TEST_CASE("Decoded xrefs reject CALL opcode bytes embedded inside instruction immediates",
          "[xref][decoder][false-positive]") {
    using namespace tessera;
    using namespace tessera::testing;

    constexpr std::uint64_t base = 0x740000;
    constexpr std::uint64_t target_value = base + 0x1007;
    auto backend = std::make_shared<FakeMemoryBackend>();
    std::vector<std::byte> code(0x1000, std::byte{0x90});

    // MOV RAX, imm64. Its immediate begins with bytes that look like CALL rel32.
    code[0] = std::byte{0x48};
    code[1] = std::byte{0xB8};
    code[2] = std::byte{0xE8};
    code[3] = std::byte{0x00};
    code[4] = std::byte{0x10};
    code[5] = std::byte{0x00};
    code[6] = std::byte{0x00};
    code[7] = std::byte{0x90};
    code[8] = std::byte{0x90};
    code[9] = std::byte{0x90};

    const std::int32_t call_displacement =
        static_cast<std::int32_t>(target_value - (base + 0x105));
    code[0x100] = std::byte{0xE8};
    std::memcpy(code.data() + 0x101, &call_displacement, sizeof(call_displacement));
    backend->map_region(Address{base}, code.size(), MemoryProtection::ExecuteRead);
    backend->poke_bytes(Address{base}, code);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange range{Address{base}, code.size()};
    const Address target{target_value};

    auto byte_scan = xref::find_calls(process, range, target);
    REQUIRE(byte_scan.has_value());
    REQUIRE(byte_scan->size() == 2);

    ScanOptions options{};
    options.filter.executable_only = true;
    auto decoded = xref::find_decoded_xrefs(process, range, target, options);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->references.size() == 1);
    REQUIRE(decoded->references.front().instruction == Address{base + 0x100});
    REQUIRE(decoded->references.front().target == target);
    REQUIRE(decoded->references.front().kind == xref::XrefKind::DirectCall);

    const std::array<Address, 3> targets{
        target, Address{target_value + 1}, target};
    auto decoded_batch = xref::find_decoded_xrefs_batch(process, range, targets, options);
    REQUIRE(decoded_batch.has_value());
    REQUIRE(decoded_batch->results.size() == targets.size());
    REQUIRE(decoded_batch->results[0].references.size() == 1);
    REQUIRE(decoded_batch->results[1].references.empty());
    REQUIRE(decoded_batch->results[2].references.size() == 1);
    REQUIRE(decoded_batch->results[2].references.front().instruction == Address{base + 0x100});
}

TEST_CASE("Decoded x86 indirect xrefs only dereference absolute ModRM operands",
          "[xref][decoder][x86]") {
    using namespace tessera;
    using namespace tessera::testing;

    constexpr std::uint64_t code_base = 0x100000;
    constexpr std::uint32_t pointer_slot = 0x102000;
    constexpr std::uint32_t target_value = 0x103000;
    auto backend = std::make_shared<FakeMemoryBackend>();
    std::array<std::byte, 0x1000> code{};
    code.fill(std::byte{0x90});

    // CALL dword ptr [disp32] — absolute addressing (FF 15 disp32).
    code[0] = std::byte{0xFF};
    code[1] = std::byte{0x15};
    std::memcpy(code.data() + 2, &pointer_slot, sizeof(pointer_slot));

    // CALL dword ptr [EBP+disp32] — base-relative, not an absolute pointer slot.
    code[0x10] = std::byte{0xFF};
    code[0x11] = std::byte{0x95};
    std::memcpy(code.data() + 0x12, &pointer_slot, sizeof(pointer_slot));

    std::array<std::byte, 0x1000> data{};
    std::memcpy(data.data(), &target_value, sizeof(target_value));
    backend->map_region(Address{code_base}, code.size(), MemoryProtection::ExecuteRead);
    backend->map_region(Address{pointer_slot}, data.size(), MemoryProtection::ReadWrite);
    backend->poke_bytes(Address{code_base}, code);
    backend->poke_bytes(Address{pointer_slot}, data);

    Process process = FakeMemoryBackend::make_process(backend, Architecture::X86);
    ScanOptions options{};
    options.filter.executable_only = true;
    auto decoded = xref::find_decoded_xrefs(
        process, AddressRange{Address{code_base}, code.size()},
        Address{target_value}, options);

    REQUIRE(decoded.has_value());
    REQUIRE(decoded->references.size() == 1);
    REQUIRE(decoded->references.front().instruction == Address{code_base});
    REQUIRE(decoded->references.front().target == Address{target_value});
    REQUIRE(decoded->references.front().kind == xref::XrefKind::IndirectCall);
}

TEST_CASE("Scanner preserves overlapping hits, alignment quotas, and strict no-access policy",
          "[scanner][overlap][policy]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    constexpr std::uint64_t base = 0x760000;
    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{base}, 0x1000, MemoryProtection::NoAccess);
    backend->map_region(Address{base + 0x1000}, 0x1000, MemoryProtection::ExecuteRead);
    const std::array<std::byte, 4> overlapping{
        std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}, std::byte{0xAA}};
    backend->poke_bytes(Address{base + 0x1100}, overlapping);

    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    Scanner scanner{process};
    const AddressRange range{Address{base}, 0x2000};
    constexpr Pattern pattern = "AA AA"_sig;

    ScanOptions best_effort{};
    best_effort.chunk_size = 0x1000;
    auto all = scanner.scan(range, pattern, best_effort);
    REQUIRE(all.has_value());
    REQUIRE(all->hits.size() == 3);
    REQUIRE(all->hits[0] == Address{base + 0x1100});
    REQUIRE(all->hits[1] == Address{base + 0x1101});
    REQUIRE(all->hits[2] == Address{base + 0x1102});
    REQUIRE(all->stats.regions_skipped == 1);

    best_effort.alignment = 2;
    auto aligned = scanner.scan(range, pattern, best_effort);
    REQUIRE(aligned.has_value());
    REQUIRE(aligned->hits.size() == 2);
    REQUIRE(aligned->hits[0] == Address{base + 0x1100});
    REQUIRE(aligned->hits[1] == Address{base + 0x1102});

    best_effort.alignment = 1;
    best_effort.max_results = 2;
    auto limited = scanner.scan(range, pattern, best_effort);
    REQUIRE(limited.has_value());
    REQUIRE(limited->hits.size() == 2);
    REQUIRE(limited->truncated);

    auto strict = scanner.scan(range, pattern, best_effort, ScanReadPolicy::Strict);
    REQUIRE_FALSE(strict.has_value());
    REQUIRE(strict.error().code == ErrorCode::AccessDenied);
}

TEST_CASE("Scanner supports concurrent read-only scans with independent workspaces",
          "[scanner][concurrency]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    constexpr std::uint64_t base = 0x770000;
    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{base}, 0x10000, MemoryProtection::ExecuteRead);
    constexpr Pattern pattern = "DE AD BE EF 48 8B"_sig;
    const std::array<std::byte, 6> signature{
        std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
        std::byte{0xEF}, std::byte{0x48}, std::byte{0x8B}};
    const std::array<std::size_t, 4> offsets{0x100, 0x2100, 0x5100, 0xE100};
    for (const std::size_t offset : offsets) {
        backend->poke_bytes(Address{base + offset}, signature);
    }

    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange range{Address{base}, 0x10000};
    std::atomic<unsigned> failures{0};
    std::array<std::jthread, 4> workers;
    for (std::size_t worker = 0; worker < workers.size(); ++worker) {
        workers[worker] = std::jthread([&, worker] {
            Scanner scanner{process};
            ScanWorkspace workspace;
            workspace.reserve(0x10000);
            ScanOptions options{};
            options.chunk_size = 0x4000;
            options.filter.executable_only = true;
            for (int iteration = 0; iteration < 8; ++iteration) {
                auto result = scanner.scan(range, pattern, options, workspace);
                if (!result || result->hits.size() != offsets.size()) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                if (result->hits[worker] != Address{base + offsets[worker]}) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                }
                const std::array<Pattern, 2> batch_patterns{pattern, "AA BB CC"_sig};
                auto batch = scanner.scan_batch(range, batch_patterns, options, workspace);
                if (!batch || batch->size() != 2 || (*batch)[0].hits.size() != offsets.size() ||
                    !(*batch)[1].hits.empty()) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    REQUIRE(failures.load(std::memory_order_relaxed) == 0);
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
