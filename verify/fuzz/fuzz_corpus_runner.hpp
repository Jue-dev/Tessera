#pragma once

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>
#include <system_error>
#include <vector>

namespace tessera::fuzz {

using InputCallback = int (*)(const std::uint8_t*, std::size_t);

// Deterministic standalone corpus replay. Coverage-guided runtimes own their
// corpus scheduling and do not compile this standalone entry point.
inline int run_corpus(int argc, char** argv, InputCallback callback) {
    if (argc < 2 || argv[1] == nullptr || callback == nullptr) {
        return 0;
    }

    std::size_t runs = 1;
    for (int i = 2; i < argc; ++i) {
        const std::string_view argument{argv[i] != nullptr ? argv[i] : ""};
        constexpr std::string_view prefix{"-runs="};
        if (!argument.starts_with(prefix)) {
            continue;
        }
        const auto value = argument.substr(prefix.size());
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), runs);
        if (error != std::errc{} || end != value.data() + value.size() || runs == 0 || runs > 100000) {
            return 2;
        }
    }

    try {
        const std::filesystem::path corpus{argv[1]};
        std::error_code error;
        std::vector<std::filesystem::path> inputs;
        if (std::filesystem::is_regular_file(corpus, error)) {
            inputs.push_back(corpus);
        } else if (std::filesystem::is_directory(corpus, error)) {
            std::filesystem::recursive_directory_iterator current{corpus, error};
            const std::filesystem::recursive_directory_iterator end;
            while (!error && current != end) {
                if (current->is_regular_file(error)) {
                    inputs.push_back(current->path());
                }
                current.increment(error);
            }
        }
        if (error || inputs.empty()) {
            return 3;
        }

        std::sort(inputs.begin(), inputs.end());
        for (const auto& path : inputs) {
            const auto file_size = std::filesystem::file_size(path, error);
            if (error || file_size > 4u * 1024u * 1024u) {
                return 4;
            }
            std::ifstream stream{path, std::ios::binary};
            if (!stream) {
                return 5;
            }
            std::vector<std::uint8_t> bytes(
                std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{});
            if (stream.bad() || bytes.size() != file_size) {
                return 6;
            }

            const std::uint8_t empty_input = 0;
            const auto* data = bytes.empty() ? &empty_input : bytes.data();
            for (std::size_t run = 0; run < runs; ++run) {
                if (callback(data, bytes.size()) != 0) {
                    return 7;
                }
            }
        }
    } catch (...) {
        return 8;
    }

    return 0;
}

} // namespace tessera::fuzz
