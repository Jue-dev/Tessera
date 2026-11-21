#include "disasm/x86_instruction_decoder.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input{line};
        std::string mode_name;
        input >> mode_name;
        const auto mode = mode_name == "x86"
            ? tessera::detail::x86::Mode::x86
            : tessera::detail::x86::Mode::x64;

        std::vector<std::byte> bytes;
        std::string token;
        while (input >> token) {
            try {
                const auto value = static_cast<std::uint8_t>(std::stoul(token, nullptr, 16));
                bytes.push_back(static_cast<std::byte>(value));
            } catch (...) {
                bytes.clear();
                break;
            }
        }

        tessera::detail::x86::DecodedInstruction decoded{};
        const bool accepted = !bytes.empty() &&
            tessera::detail::x86::decode_instruction(
                bytes.data(), bytes.size(), mode, decoded);
        std::cout << (accepted ? 1 : 0) << ' '
                  << (accepted ? static_cast<unsigned int>(decoded.length) : 0u)
                  << '\n';
    }
    return 0;
}
