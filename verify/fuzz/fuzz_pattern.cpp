#include "tessera/pattern/pattern.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    auto pat = tessera::Pattern::parse(input);
    if (pat.has_value()) {
        const std::span<const std::byte> haystack(reinterpret_cast<const std::byte*>(data), size);
        pat->search(haystack, haystack.size(), [](std::size_t) { return false; });
    }
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main() {
    const char sample[] = "48 8B ? ? 90";
    return LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif // !defined(TESSERA_LIBFUZZER)
