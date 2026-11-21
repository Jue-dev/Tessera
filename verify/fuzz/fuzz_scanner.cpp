#include "FakeMemoryBackend.hpp"

#include "fuzz_corpus_runner.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/scanner/xref.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>
namespace {
constexpr std::uint64_t kFuzzBase = 0x20000000ULL;
constexpr std::size_t kPageSize = 4096;
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) return 0;
    auto backend = std::make_shared<tessera::testing::FakeMemoryBackend>();
    backend->map_region(tessera::Address{kFuzzBase}, kPageSize,
                        tessera::MemoryProtection::ReadWrite);
    backend->map_region(tessera::Address{kFuzzBase + kPageSize}, kPageSize,
                        tessera::MemoryProtection::ReadWrite | tessera::MemoryProtection::Guard);
    backend->map_region(tessera::Address{kFuzzBase + 2u * kPageSize}, kPageSize,
                        tessera::MemoryProtection::NoAccess);
    backend->map_region(tessera::Address{kFuzzBase + 3u * kPageSize}, kPageSize,
                        tessera::MemoryProtection::ExecuteRead);
    const std::size_t copied = (std::min)(size, 2u * kPageSize);
    if (copied != 0) {
        const std::span<const std::byte> bytes{
            reinterpret_cast<const std::byte*>(data), copied};
        backend->poke_bytes(tessera::Address{kFuzzBase}, bytes);
    }
    auto process = tessera::testing::FakeMemoryBackend::make_process(
        backend, tessera::Architecture::X64);
    const tessera::AddressRange image{tessera::Address{kFuzzBase}, 4u * kPageSize};
    const std::size_t pattern_size = (std::min)(size, std::size_t{128});
    if (pattern_size != 0) {
        const std::string_view text{reinterpret_cast<const char*>(data), pattern_size};
        auto pattern = tessera::Pattern::parse(text);
        if (pattern) {
            const std::size_t haystack_size = (std::min)(size, 4u * kPageSize);
            const std::span<const std::byte> haystack{
                reinterpret_cast<const std::byte*>(data), haystack_size};
            std::vector<std::size_t> expected;
            for (std::size_t offset = 0; offset + pattern->size() <= haystack.size(); ++offset) {
                if (pattern->matches(haystack.subspan(offset))) {
                    expected.push_back(offset);
                }
            }
            std::vector<std::size_t> actual;
            pattern->search(haystack, haystack.size(), [&](std::size_t offset) {
                actual.push_back(offset);
                return true;
            });
            if (actual != expected) {
                std::abort();
            }

            tessera::ScanOptions options{};
            options.chunk_size = 1u + (size % 1024u);
            options.alignment = 1u + (size % 16u);
            options.max_results = 64;
            tessera::Scanner scanner{process};
            (void)scanner.scan(image, *pattern, options);
            (void)scanner.scan(image, *pattern, options, tessera::ScanReadPolicy::Strict);
            (void)scanner.find_first(image, *pattern, options);
            (void)scanner.find_unique(image, *pattern, options);
            const std::array<tessera::Pattern, 2> batch_patterns{*pattern, *pattern};
            (void)scanner.scan_batch(image, batch_patterns, options);
        }
    }
    const tessera::Address target{kFuzzBase + (size % kPageSize)};
    tessera::ScanOptions options{};
    options.chunk_size = 1u + (size % 1024u);
    options.max_results = 64;
    (void)tessera::xref::find_pointer_refs(process, image, target, options);
    const std::array<tessera::Address, 2> targets{target, tessera::Address{kFuzzBase}};
    (void)tessera::xref::find_pointer_refs_batch(process, image, targets, options);
    (void)tessera::xref::find_calls(process, image, target, options);
    (void)tessera::xref::find_jumps(process, image, target, options);
    (void)tessera::xref::find_conditional_branches(process, image, target, options);
    (void)tessera::xref::find_indirect_refs(process, image, target, options);
    (void)tessera::xref::find_decoded_xrefs(process, image, target, options);
    (void)tessera::xref::find_decoded_xrefs_batch(process, image, targets, options);
    return 0;
}
#if !defined(TESSERA_LIBFUZZER)
int main(int argc, char** argv) {
    if (argc > 1) {
        return tessera::fuzz::run_corpus(argc, argv, &LLVMFuzzerTestOneInput);
    }
    constexpr char sample[] = "48 8B ? ? 90 E8 00 00 00 00";
    return LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif
