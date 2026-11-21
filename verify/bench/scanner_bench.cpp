#include "tessera/tessera.hpp"

#include <array>
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

    std::cout << "Benchmark 1: Pattern::search (4 MiB)\n"
              << "  Iterations : " << pat_metrics.iterations << "\n"
              << "  Min (us)   : " << pat_metrics.min.count() / 1000.0 << "\n"
              << "  Mean (us)  : " << pat_metrics.mean.count() / 1000.0 << "\n"
              << "  Max (us)   : " << pat_metrics.max.count() / 1000.0 << "\n\n";

    // 2. RttiCatalog + BinaryExplorer + PythonBridgeScanner over 64 KiB synthetic module
    constexpr std::uint64_t kModBase = 0x140000000ULL;
    auto backend = std::make_shared<testing::FakeMemoryBackend>();
    backend->map_region(Address{kModBase + 0x1000}, 0x8000, MemoryProtection::ExecuteRead);
    auto& rdata = backend->map_region(Address{kModBase + 0x9000}, 0x8000, MemoryProtection::Read);

    const char* sample_td = ".?AVBenchmarkEntity@Engine@@";
    std::memcpy(rdata.storage.data() + 0x100 + 16, sample_td, std::strlen(sample_td) + 1);
    const char* sample_py = "builtin_function_or_method";
    std::memcpy(rdata.storage.data() + 0x200, sample_py, std::strlen(sample_py) + 1);

    Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange mod_range{Address{kModBase}, 0x11000};

    auto disc_metrics = profiling::run_benchmark(20, [&]() {
        auto tds = rtti::BinaryExplorer::scan_all_type_descriptors(proc, mod_range);
        auto py = rtti::PythonBridgeScanner::detect_environment(proc, mod_range);
        if (!tds.has_value() || tds->empty() || !py.has_value()) {
            std::abort();
        }
    });

    if (json) {
        const auto throughput = [&](std::chrono::nanoseconds duration, std::size_t bytes) {
            const double seconds = static_cast<double>(duration.count()) / 1.0e9;
            return seconds > 0.0 ? (static_cast<double>(bytes) / seconds) / 1.0e6 : 0.0;
        };
        std::cout << "{\\"benchmarks\\":["
                  << "{\\"name\\":\\"pattern_search_wildcard_4mib\\",\\"iterations\\":" << pat_metrics.iterations
                  << ",\\"ns_per_op\\":" << pat_metrics.mean.count() << ",\\"mb_per_s\\":" << throughput(pat_metrics.mean, buffer.size()) << "},"
                  << "{\\"name\\":\\"pattern_search_exact_4mib\\",\\"iterations\\":" << exact_metrics.iterations
                  << ",\\"ns_per_op\\":" << exact_metrics.mean.count() << ",\\"mb_per_s\\":" << throughput(exact_metrics.mean, buffer.size()) << "},"
                  << "{\\"name\\":\\"pattern_search_nibble_4mib\\",\\"iterations\\":" << nibble_metrics.iterations
                  << ",\\"ns_per_op\\":" << nibble_metrics.mean.count() << ",\\"mb_per_s\\":" << throughput(nibble_metrics.mean, buffer.size()) << "},"
                  << "{\\"name\\":\\"scanner_chunked_4mib\\",\\"iterations\\":" << scanner_metrics.iterations
                  << ",\\"ns_per_op\\":" << scanner_metrics.mean.count() << ",\\"mb_per_s\\":" << throughput(scanner_metrics.mean, buffer.size()) << "},"
                  << "{\\"name\\":\\"scanner_batch_four_patterns_4mib\\",\\"iterations\\":" << batch_metrics.iterations
                  << ",\\"ns_per_op\\":" << batch_metrics.mean.count() << ",\\"mb_per_s\\":" << throughput(batch_metrics.mean, buffer.size()) << "},"
                  << "{\\"name\\":\\"rtti_python_discovery_64k\\",\\"iterations\\":" << disc_metrics.iterations
                  << ",\\"ns_per_op\\":" << disc_metrics.mean.count() << ",\\"mb_per_s\\":" << throughput(disc_metrics.mean, 0x10000u) << "}] }\\n";
        return 0;
    }


    std::cout << "Benchmark 2: BinaryExplorer + PythonBridgeScanner (64 KiB module)\n"
              << "  Iterations : " << disc_metrics.iterations << "\n"
              << "  Min (us)   : " << disc_metrics.min.count() / 1000.0 << "\n"
              << "  Mean (us)  : " << disc_metrics.mean.count() / 1000.0 << "\n"
              << "  Max (us)   : " << disc_metrics.max.count() / 1000.0 << "\n";


    return 0;
}
