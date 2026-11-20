#include "tessera/tessera.hpp"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <vector>\n#include <array>\n#include <cstdint>\n\n#include "hook/backends/x86_instruction_decoder.hpp"

#include "FakeMemoryBackend.hpp"



namespace {

void write_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::byte>(value & 0xFFu);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8u) & 0xFFu);
}

void write_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8u)) & 0xFFu);
    }
}

void write_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8u)) & 0xFFu);
    }
}

[[nodiscard]] std::vector<std::byte> make_benchmark_pe64() {
    std::vector<std::byte> bytes(0x400);
    write_u16(bytes, 0x00, 0x5A4D);
    write_u32(bytes, 0x3C, 0x80);
    write_u32(bytes, 0x80, 0x00004550);
    write_u16(bytes, 0x84, 0x8664);
    write_u16(bytes, 0x86, 1);
    write_u32(bytes, 0x88, 0x65A1B2C3);
    write_u16(bytes, 0x94, 0xF0);
    write_u16(bytes, 0x98, 0x020B);
    write_u32(bytes, 0x98 + 16, 0x1000);
    write_u64(bytes, 0x98 + 24, 0x140000000ull);
    write_u32(bytes, 0x98 + 32, 0x1000);
    write_u32(bytes, 0x98 + 36, 0x200);
    write_u32(bytes, 0x98 + 56, 0x2000);
    write_u32(bytes, 0x98 + 60, 0x200);
    write_u32(bytes, 0x98 + 108, 16);

    constexpr std::size_t section = 0x188;
    constexpr char section_name[] = ".text";
    for (std::size_t i = 0; i < sizeof(section_name) - 1; ++i) {
        bytes[section + i] = static_cast<std::byte>(section_name[i]);
    }
    write_u32(bytes, section + 8, 0x100);
    write_u32(bytes, section + 12, 0x1000);
    write_u32(bytes, section + 16, 0x200);
    write_u32(bytes, section + 20, 0x200);
    write_u32(bytes, section + 36, 0x60000020);
    return bytes;
}

void print_metrics(const char* title, const tessera::profiling::BenchmarkMetrics& metrics) {
    std::cout << title << "\\n"
              << "  Iterations : " << metrics.iterations << "\\n"
              << "  Min (us)   : " << metrics.min.count() / 1000.0 << "\\n"
              << "  Mean (us)  : " << metrics.mean.count() / 1000.0 << "\\n"
              << "  Max (us)   : " << metrics.max.count() / 1000.0 << "\\n\\n";
}

} // namespace
\nint main() {
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
