#include <array>
#include <cstddef>
#include <cstdlib>
#include <iostream>

#include "hook/backends/x86_instruction_decoder.hpp"
#include "tessera/profiling/profiling.hpp"

int main() {
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

    std::cout << "Benchmark: x64 instruction decoder (RIP-relative MOV)\n"
              << "  Iterations : " << metrics.iterations << "\n"
              << "  Min (us)   : " << metrics.min.count() / 1000.0 << "\n"
              << "  Mean (us)  : " << metrics.mean.count() / 1000.0 << "\n"
              << "  Max (us)   : " << metrics.max.count() / 1000.0 << "\n";
    return 0;
}
