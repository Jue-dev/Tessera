#include "tessera/tessera.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <vector>

#include "FakeMemoryBackend.hpp"


int main() {
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

    std::cout << "Benchmark 2: BinaryExplorer + PythonBridgeScanner (64 KiB module)\n"
              << "  Iterations : " << disc_metrics.iterations << "\n"
              << "  Min (us)   : " << disc_metrics.min.count() / 1000.0 << "\n"
              << "  Mean (us)  : " << disc_metrics.mean.count() / 1000.0 << "\n"
              << "  Max (us)   : " << disc_metrics.max.count() / 1000.0 << "\n";


    return 0;
}
