#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string_view>

#include "disasm/x86_instruction_decoder.hpp"
#include "tessera/profiling/profiling.hpp"

int main(int argc, char** argv) {
    const bool json = argc > 1 && std::string_view{argv[1]} == "--json";
    using namespace tessera;

    constexpr std::array<std::byte, 7> instruction{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}, std::byte{0x34},
        std::byte{0x12}, std::byte{0x00}, std::byte{0x00}};
    const auto metrics = profiling::run_benchmark(10000, [&]() {
        detail::x86::DecodedInstruction decoded{};
        if (!detail::x86::decode_instruction(
                instruction.data(), instruction.size(), detail::x86::Mode::x64, decoded) ||
            decoded.length != instruction.size() || !decoded.has_rip_relative_operand) {
            std::abort();
        }
    });

    if (json) {
        const double seconds = static_cast<double>(metrics.mean.count()) / 1.0e9;
        const double mb_per_s = seconds > 0.0 ? (instruction.size() / seconds) / 1.0e6 : 0.0;
        std::cout << "{\"name\":\"decoder_x64_rip_mov\",\"iterations\":" << metrics.iterations
                  << ",\"ns_per_op\":" << metrics.mean.count()
                  << ",\"mb_per_s\":" << mb_per_s << "}\n";
        return 0;
    }

    std::cout << "Benchmark: x64 instruction decoder (RIP-relative MOV)\n"
              << "  Iterations : " << metrics.iterations << "\n"
              << "  Min (us)   : " << metrics.min.count() / 1000.0 << "\n"
              << "  Mean (us)  : " << metrics.mean.count() / 1000.0 << "\n"
              << "  Max (us)   : " << metrics.max.count() / 1000.0 << "\n";
    return 0;
}
