#include "FakeMemoryBackend.hpp"

#include "fuzz_corpus_runner.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/rtti/rtti.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {
constexpr std::uint64_t kFuzzBase = 0x10000000ULL;
constexpr std::size_t kMaxFuzzBytes = 64 * 1024;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        return 0;
    }

    const std::size_t bounded_size = (std::min)(size, kMaxFuzzBytes);
    // Keep one readable zero byte after the fuzz payload so bounded C-string
    // probes can inspect a candidate that ends exactly at the input boundary.
    const std::size_t region_size = bounded_size + 1;

    auto backend = std::make_shared<tessera::testing::FakeMemoryBackend>();
    backend->map_region(
        tessera::Address{kFuzzBase},
        region_size,
        tessera::MemoryProtection::ExecuteReadWrite);

    if (bounded_size != 0) {
        const std::span<const std::byte> bytes{
            reinterpret_cast<const std::byte*>(data), bounded_size};
        backend->poke_bytes(tessera::Address{kFuzzBase}, bytes);
    }

    auto process = tessera::testing::FakeMemoryBackend::make_process(
        backend, tessera::Architecture::X64);
    const tessera::AddressRange range{
        tessera::Address{kFuzzBase}, region_size};

    (void)tessera::rtti::BinaryExplorer::scan_all_type_descriptors(process, range);
    (void)tessera::rtti::BinaryExplorer::scan_strings(process, range);
    (void)tessera::rtti::RttiCatalog::discover_all(process, range);

    // Exercise the 32-bit absolute-VA RTTI layout parser against the same
    // bounded bytes as well as the x64 RVA-based layout.
    auto x86_process = tessera::testing::FakeMemoryBackend::make_process(
        backend, tessera::Architecture::X86);
    (void)tessera::rtti::BinaryExplorer::scan_all_type_descriptors(x86_process, range);
    (void)tessera::rtti::BinaryExplorer::scan_strings(x86_process, range);
    (void)tessera::rtti::RttiCatalog::discover_all(x86_process, range);
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main(int argc, char** argv) {
    if (argc > 1) {
        return tessera::fuzz::run_corpus(argc, argv, &LLVMFuzzerTestOneInput);
    }
    constexpr char sample[] = ".?AVFuzzType@Tessera@@";
    return LLVMFuzzerTestOneInput(
        reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif // !defined(TESSERA_LIBFUZZER)
