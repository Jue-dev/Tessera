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

int main() {
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

    std::cout << "rtti discovery descriptors=" << type_count
              << " iterations=" << metrics.iterations
              << " mean_ns=" << metrics.mean.count() << '\n';
    return 0;
}
