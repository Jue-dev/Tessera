#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

#include "tessera/module/pe_image.hpp"
#include "tessera/profiling/profiling.hpp"

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

} // namespace

int main(int argc, char** argv) {
    const bool json = argc > 1 && std::string_view{argv[1]} == "--json";
    using namespace tessera;

    const auto pe_bytes = make_benchmark_pe64();
    const auto metrics = profiling::run_benchmark(1000, [&]() {
        auto image = PeImage::from_raw_bytes(pe_bytes);
        if (!image.has_value() || image->sections().size() != 1) {
            std::abort();
        }
        (void)image->sections();
        (void)image->exports();
        (void)image->imports();
        (void)image->exception_functions();
        (void)image->code_view();
    });

    if (json) {
        const double seconds = static_cast<double>(metrics.mean.count()) / 1.0e9;
        const double mb_per_s = seconds > 0.0 ? (pe_bytes.size() / seconds) / 1.0e6 : 0.0;
        std::cout << "{\"name\":\"pe32plus_raw_parse\",\"iterations\":" << metrics.iterations
                  << ",\"ns_per_op\":" << metrics.mean.count()
                  << ",\"mb_per_s\":" << mb_per_s << "}\n";
        return 0;
    }

    std::cout << "Benchmark: PE32+ raw parse (one section, 1 KiB image)\n"
              << "  Iterations : " << metrics.iterations << "\n"
              << "  Min (us)   : " << metrics.min.count() / 1000.0 << "\n"
              << "  Mean (us)  : " << metrics.mean.count() / 1000.0 << "\n"
              << "  Max (us)   : " << metrics.max.count() / 1000.0 << "\n";
    return 0;
}
