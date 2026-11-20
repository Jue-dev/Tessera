#include "tessera/module/pe_image.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        return 0;
    }
    const std::byte empty_input{};
    const auto* const bytes = data != nullptr
                                 ? reinterpret_cast<const std::byte*>(data)
                                 : &empty_input;
    const std::span<const std::byte> raw(bytes, size);
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
