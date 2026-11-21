#include "tessera/json/json.hpp"

#include "fuzz_corpus_runner.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    auto val = tessera::json::parse(text);
    if (val.has_value()) {
        (void)tessera::json::write(*val);
    }
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main(int argc, char** argv) {
    if (argc > 1) {
        return tessera::fuzz::run_corpus(argc, argv, &LLVMFuzzerTestOneInput);
    }
    const char sample[] = R"({"key": [1, true, "val"]})";
    return LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif // !defined(TESSERA_LIBFUZZER)
