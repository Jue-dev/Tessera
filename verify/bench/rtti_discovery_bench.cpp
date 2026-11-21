#include "FakeMemoryBackend.hpp"
#include "tessera/profiling/profiling.hpp"
#include "tessera/rtti/discovery.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
    const bool json = argc > 1 && std::string_view{argv[1]} == "--json";
    using namespace tessera;
    using namespace tessera::testing;

    constexpr std::uint64_t base = 0x140000000ULL;
    constexpr std::size_t region_size = 0x10000;
    constexpr std::size_t type_count = 64;
    constexpr std::size_t descriptor_stride = 0x100;
    constexpr std::size_t name_offset = 16;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& region = backend->map_region(Address{base}, region_size, MemoryProtection::Read);
    for (std::size_t i = 0; i < type_count; ++i) {
        const std::string name = ".?AVBenchType" + std::to_string(i) + "@@";
        const auto offset = 0x100 + i * descriptor_stride + name_offset;
        std::memcpy(region.storage.data() + offset, name.c_str(), name.size() + 1);
    }

    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange module_range{Address{base}, region_size};
    const auto initial = rtti::BinaryExplorer::scan_all_type_descriptors(process, module_range);
    if (!initial || initial->size() != type_count) {
        std::cerr << "RTTI benchmark fixture discovery mismatch\n";
        return 1;
    }

    const auto metrics = profiling::run_benchmark(20, [&] {
        const auto result = rtti::BinaryExplorer::scan_all_type_descriptors(process, module_range);
        if (!result || result->size() != type_count) {
            std::abort();
        }
    });

    if (json) {
        const double seconds = static_cast<double>(metrics.mean.count()) / 1.0e9;
        const double mb_per_s = seconds > 0.0 ? (region_size / seconds) / 1.0e6 : 0.0;
        std::cout << "{\"name\":\"rtti_discovery_64_types\",\"iterations\":" << metrics.iterations
                  << ",\"ns_per_op\":" << metrics.mean.count()
                  << ",\"mb_per_s\":" << mb_per_s << "}\n";
        return 0;
    }

    std::cout << "rtti discovery descriptors=" << type_count
              << " iterations=" << metrics.iterations
              << " mean_ns=" << metrics.mean.count() << '\n';
    return 0;
}
