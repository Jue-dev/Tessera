#include "tessera/module/pe_image.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::byte> raw(reinterpret_cast<const std::byte*>(data), size);
    auto pe = tessera::PeImage::from_raw_bytes(raw);
    if (pe.has_value()) {
        (void)pe->exports();
        (void)pe->imports();
        (void)pe->sections();
        (void)pe->exception_functions();
        (void)pe->code_view();
    }
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main() {
    const std::uint8_t sample[64]{};
    return LLVMFuzzerTestOneInput(sample, sizeof(sample));
}
#endif // !defined(TESSERA_LIBFUZZER)
