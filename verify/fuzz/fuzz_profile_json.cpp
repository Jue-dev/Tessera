#include "tessera/json/json.hpp"

#include "fuzz_corpus_runner.hpp"
#include "tessera/profile/profile_json.hpp"
#include "tessera/targets/target_profile_json.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        return 0;
    }
    const char* const input = data != nullptr ? reinterpret_cast<const char*>(data) : "";
    const std::string_view text(input, size);
    auto root = tessera::json::parse(text);
    if (!root) {
        return 0;
    }

    // Both parsers accept a JsonValue root and must remain robust against
    // arbitrary, structurally valid JSON values and malformed profile schemas.
    (void)tessera::profile::deserialize_profile_from_json(*root);
    (void)tessera::targets::deserialize_target_profile_from_json(*root);
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main(int argc, char** argv) {
    if (argc > 1) {
        return tessera::fuzz::run_corpus(argc, argv, &LLVMFuzzerTestOneInput);
    }
    constexpr char sample[] =
        R"({"formatVersion":1,"schemaVersion":1,"revision":0,"id":"fuzz-seed","values":{},"profileVersion":1,"application":{"applicationId":"sample","executables":["sample.exe"]},"targets":[]})";
    return LLVMFuzzerTestOneInput(
        reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif // !defined(TESSERA_LIBFUZZER)
