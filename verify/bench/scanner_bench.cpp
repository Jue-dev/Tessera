#include "tessera/tessera.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "FakeMemoryBackend.hpp"


int main(int argc, char** argv) {
    const bool json = argc > 1 && std::string_view{argv[1]} == "--json";
    using namespace tessera;
    using namespace tessera::literals;

    // 1. Pattern::search over 4 MiB buffer
    std::vector<std::byte> buffer(4 * 1024 * 1024, std::byte{0x90});
    const std::uint8_t needle[] = {0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x48, 0x85, 0xC0};
    const std::size_t pos = buffer.size() - 64;
    for (std::size_t i = 0; i < sizeof(needle); ++i) {
        buffer[pos + i] = static_cast<std::byte>(needle[i]);
    }

    constexpr auto pat = "48 8B 05 ? ? ? ? 48 85 C0"_sig;

    auto pat_metrics = profiling::run_benchmark(25, [&]() {
        std::optional<std::size_t> found;
        pat.search(buffer, buffer.size(), [&](std::size_t idx) {
            found = idx;
            return false;
        });
        if (!found.has_value() || *found != pos) {
            std::abort();
        }
    });

    constexpr auto exact_pat = "48 8B 05 12 34 56 78 48 85 C0"_sig;
    constexpr auto nibble_pat = "4? 8B 05 1? 34 ?? ?? 48 85 C0"_sig;

    auto exact_metrics = profiling::run_benchmark(25, [&]() {
        std::optional<std::size_t> found;
        exact_pat.search(buffer, buffer.size(), [&](std::size_t idx) {
            found = idx;
            return false;
        });
        if (!found || *found != pos) {
            std::abort();
        }
    });

    auto nibble_metrics = profiling::run_benchmark(25, [&]() {
        std::optional<std::size_t> found;
        nibble_pat.search(buffer, buffer.size(), [&](std::size_t idx) {
            found = idx;
            return false;
        });
        if (!found || *found != pos) {
            std::abort();
        }
    });

    constexpr std::uint64_t kScanBase = 0x30000000ULL;
    auto scan_backend = std::make_shared<testing::FakeMemoryBackend>();
    scan_backend->map_region(Address{kScanBase}, buffer.size(), MemoryProtection::ExecuteRead);
    scan_backend->poke_bytes(Address{kScanBase}, buffer);
    Process scan_process = testing::FakeMemoryBackend::make_process(
        scan_backend, Architecture::X64);
    Scanner scanner{scan_process};
    const AddressRange scan_range{Address{kScanBase}, buffer.size()};
    ScanOptions scan_options{};
    scan_options.chunk_size = 256u * 1024u;
    scan_options.max_results = 16;

    auto scanner_metrics = profiling::run_benchmark(10, [&]() {
        auto result = scanner.scan(scan_range, pat, scan_options);
        if (!result || result->hits.size() != 1 ||
            result->hits.front() != Address{kScanBase + pos}) {
            std::abort();
        }
    });

    ScanWorkspace reusable_workspace;
    reusable_workspace.reserve(scan_options.chunk_size + pat.size() - 1);
    auto workspace_metrics = profiling::run_benchmark(10, [&]() {
        auto result = scanner.scan(scan_range, pat, scan_options, reusable_workspace);
        if (!result || result->hits.size() != 1 ||
            result->hits.front() != Address{kScanBase + pos}) {
            std::abort();
        }
    });

    auto streaming_metrics = profiling::run_benchmark(10, [&]() {
        std::optional<Address> found;
        auto result = scanner.scan_streaming(
            scan_range, pat, scan_options,
            [&](Address address) {
                found = address;
                return false;
            },
            &reusable_workspace);
        if (!result || !result->cancelled || !result->hits.empty() ||
            found != Address{kScanBase + pos}) {
            std::abort();
        }
    });

    const std::array<Pattern, 4> batch_patterns{
        pat, exact_pat, nibble_pat, "90 90 90 90"_sig};
    ScanOptions batch_options{};
    batch_options.chunk_size = scan_options.chunk_size;
    batch_options.max_results = 8;
    auto batch_metrics = profiling::run_benchmark(10, [&]() {
        auto result = scanner.scan_batch(scan_range, batch_patterns, batch_options);
        if (!result || result->size() != 4 ||
            (*result)[0].hits.size() != 1 ||
            (*result)[1].hits.size() != 1 ||
            (*result)[2].hits.size() != 1 ||
            (*result)[3].hits.size() != 8) {
            std::abort();
        }
    });

    constexpr auto prolog_pat = "48 89 5C 24 08 57 48 83 EC 20"_sig;
    std::vector<std::byte> prolog_buffer(buffer.size(), std::byte{0x90});
    const std::array<std::byte, 10> prolog_bytes{
        std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24}, std::byte{0x08},
        std::byte{0x57}, std::byte{0x48}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x20}};
    constexpr std::size_t prolog_stride = 64;
    for (std::size_t offset = 0; offset + prolog_bytes.size() <= prolog_buffer.size();
         offset += prolog_stride) {
        std::memcpy(prolog_buffer.data() + offset, prolog_bytes.data(), prolog_bytes.size());
    }
    const std::size_t expected_prologs = (prolog_buffer.size() + prolog_stride - 1) / prolog_stride;
    auto prolog_metrics = profiling::run_benchmark(10, [&]() {
        std::size_t found = 0;
        prolog_pat.search(prolog_buffer, prolog_buffer.size(), [&](std::size_t) {
            ++found;
            return true;
        });
        if (found != expected_prologs) {
            std::abort();
        }
    });

    constexpr auto leading_pat = "?? ?? 48 8B 05 12 34 56 78 48 85 C0"_sig;
    auto leading_metrics = profiling::run_benchmark(25, [&]() {
        std::optional<std::size_t> found;
        leading_pat.search(buffer, buffer.size(), [&](std::size_t idx) {
            found = idx;
            return false;
        });
        if (!found || *found != pos - 2) {
            std::abort();
        }
    });

    std::vector<Pattern> fifty_patterns;
    fifty_patterns.reserve(50);
    fifty_patterns.push_back(exact_pat);
    for (std::uint16_t value = 0; value < 49; ++value) {
        const std::array<std::byte, 3> bytes{
            static_cast<std::byte>(0xA0u + value), std::byte{0xFE}, std::byte{0xED}};
        auto candidate = Pattern::from_bytes(bytes);
        if (!candidate) {
            std::abort();
        }
        fifty_patterns.push_back(*candidate);
    }

    auto fifty_separate_metrics = profiling::run_benchmark(3, [&]() {
        for (std::size_t index = 0; index < fifty_patterns.size(); ++index) {
            auto result = scanner.scan(scan_range, fifty_patterns[index], batch_options);
            if (!result || result->hits.size() != (index == 0 ? 1u : 0u)) {
                std::abort();
            }
        }
    });

    auto fifty_batch_metrics = profiling::run_benchmark(10, [&]() {
        auto result = scanner.scan_batch(scan_range, fifty_patterns, batch_options);
        if (!result || result->size() != fifty_patterns.size() ||
            (*result)[0].hits.size() != 1) {
            std::abort();
        }
        for (std::size_t i = 1; i < result->size(); ++i) {
            if (!(*result)[i].hits.empty()) {
                std::abort();
            }
        }
    });

    constexpr std::uint64_t kXrefBase = 0x31000000ULL;
    constexpr std::uint64_t kXrefTarget = kXrefBase + 0x3000ULL;
    auto xref_backend = std::make_shared<testing::FakeMemoryBackend>();
    std::vector<std::byte> xref_code(0x4000, std::byte{0x90});
    constexpr std::size_t call_offset = 0x100;
    xref_code[call_offset] = std::byte{0xE8};
    const std::int32_t call_rel = static_cast<std::int32_t>(
        kXrefTarget - (kXrefBase + call_offset + 5));
    std::memcpy(xref_code.data() + call_offset + 1, &call_rel, sizeof(call_rel));
    xref_backend->map_region(Address{kXrefBase}, xref_code.size(), MemoryProtection::ExecuteRead);
    xref_backend->poke_bytes(Address{kXrefBase}, xref_code);
    Process xref_process = testing::FakeMemoryBackend::make_process(
        xref_backend, Architecture::X64);
    const AddressRange xref_range{Address{kXrefBase}, xref_code.size()};
    const Address xref_target{kXrefTarget};
    ScanOptions xref_options{};
    xref_options.filter.executable_only = true;

    auto raw_xref_metrics = profiling::run_benchmark(20, [&]() {
        auto result = xref::find_calls(xref_process, xref_range, xref_target, xref_options);
        if (!result || result->size() != 1 ||
            result->front() != Address{kXrefBase + call_offset}) {
            std::abort();
        }
    });

    auto decoded_xref_metrics = profiling::run_benchmark(5, [&]() {
        auto result = xref::find_decoded_xrefs(xref_process, xref_range, xref_target, xref_options);
        if (!result || result->references.size() != 1 ||
            result->references.front().instruction != Address{kXrefBase + call_offset}) {
            std::abort();
        }
    });

    if (json) {
        const auto throughput = [&](std::chrono::nanoseconds duration, std::size_t bytes) {
            const double seconds = static_cast<double>(duration.count()) / 1.0e9;
            return seconds > 0.0 ? (static_cast<double>(bytes) / seconds) / 1.0e6 : 0.0;
        };
        std::cout << "{\"benchmarks\":["
                  << "{\"name\":\"pattern_masked_4mib\",\"iterations\":" << pat_metrics.iterations
                  << ",\"ns_per_op\":" << pat_metrics.mean.count() << ",\"mb_per_s\":" << throughput(pat_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"pattern_exact_literal_4mib\",\"iterations\":" << exact_metrics.iterations
                  << ",\"ns_per_op\":" << exact_metrics.mean.count() << ",\"mb_per_s\":" << throughput(exact_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"pattern_high_frequency_prolog_4mib\",\"iterations\":" << prolog_metrics.iterations
                  << ",\"ns_per_op\":" << prolog_metrics.mean.count() << ",\"mb_per_s\":" << throughput(prolog_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"pattern_leading_wildcard_4mib\",\"iterations\":" << leading_metrics.iterations
                  << ",\"ns_per_op\":" << leading_metrics.mean.count() << ",\"mb_per_s\":" << throughput(leading_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"pattern_dense_nibble_4mib\",\"iterations\":" << nibble_metrics.iterations
                  << ",\"ns_per_op\":" << nibble_metrics.mean.count() << ",\"mb_per_s\":" << throughput(nibble_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"scanner_workspace_reused_4mib\",\"iterations\":" << workspace_metrics.iterations
                  << ",\"ns_per_op\":" << workspace_metrics.mean.count() << ",\"mb_per_s\":" << throughput(workspace_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"scanner_streaming_first_match_4mib\",\"iterations\":" << streaming_metrics.iterations
                  << ",\"ns_per_op\":" << streaming_metrics.mean.count() << ",\"mb_per_s\":" << throughput(streaming_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"scanner_50_patterns_separate_4mib\",\"iterations\":" << fifty_separate_metrics.iterations
                  << ",\"ns_per_op\":" << fifty_separate_metrics.mean.count() << ",\"mb_per_s\":" << throughput(fifty_separate_metrics.mean, buffer.size() * fifty_patterns.size()) << "},"
                  << "{\"name\":\"scanner_50_patterns_batch_4mib\",\"iterations\":" << fifty_batch_metrics.iterations
                  << ",\"ns_per_op\":" << fifty_batch_metrics.mean.count() << ",\"mb_per_s\":" << throughput(fifty_batch_metrics.mean, buffer.size()) << "},"
                  << "{\"name\":\"xref_raw_pattern_16kib\",\"iterations\":" << raw_xref_metrics.iterations
                  << ",\"ns_per_op\":" << raw_xref_metrics.mean.count() << ",\"mb_per_s\":" << throughput(raw_xref_metrics.mean, xref_code.size()) << "},"
                  << "{\"name\":\"xref_decoder_verified_16kib\",\"iterations\":" << decoded_xref_metrics.iterations
                  << ",\"ns_per_op\":" << decoded_xref_metrics.mean.count() << ",\"mb_per_s\":" << throughput(decoded_xref_metrics.mean, xref_code.size()) << "}] }\n";
        return 0;
    }

    const auto print_metric = [](int index, std::string_view name, const auto& metrics,
                                  std::size_t bytes) {
        const double seconds = static_cast<double>(metrics.mean.count()) / 1.0e9;
        const double mb_per_s = seconds > 0.0
                                    ? (static_cast<double>(bytes) / seconds) / 1.0e6
                                    : 0.0;
        std::cout << "Benchmark " << index << ": " << name << "\n"
                  << "  Iterations : " << metrics.iterations << "\n"
                  << "  Min (us)   : " << metrics.min.count() / 1000.0 << "\n"
                  << "  Mean (us)  : " << metrics.mean.count() / 1000.0 << "\n"
                  << "  Max (us)   : " << metrics.max.count() / 1000.0 << "\n"
                  << "  Throughput : " << mb_per_s << " MB/s\n\n";
    };
    print_metric(1, "Masked Pattern::search (4 MiB)", pat_metrics, buffer.size());
    print_metric(2, "Exact literal Pattern::search (4 MiB)", exact_metrics, buffer.size());
    print_metric(3, "Common x64 prolog Pattern::search (4 MiB)", prolog_metrics, buffer.size());
    print_metric(4, "Leading wildcard Pattern::search (4 MiB)", leading_metrics, buffer.size());
    print_metric(5, "Dense nibble mask Pattern::search (4 MiB)", nibble_metrics, buffer.size());
    print_metric(6, "Reusable ScanWorkspace (4 MiB)", workspace_metrics, buffer.size());
    print_metric(7, "Streaming first-match callback (4 MiB)", streaming_metrics, buffer.size());
    print_metric(8, "50 patterns scanned separately (4 MiB each)", fifty_separate_metrics,
                 buffer.size() * fifty_patterns.size());
    print_metric(9, "50 patterns scanned in one batch (4 MiB)", fifty_batch_metrics, buffer.size());
    print_metric(10, "Raw byte-pattern CALL xref (16 KiB)", raw_xref_metrics, xref_code.size());
    print_metric(11, "Decoder-verified CALL xref (16 KiB)", decoded_xref_metrics, xref_code.size());

    return 0;
}
