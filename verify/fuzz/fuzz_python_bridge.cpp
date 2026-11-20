#include "FakeMemoryBackend.hpp"
#include "tessera/rtti/python_bridge.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
namespace {
constexpr std::uint64_t kFuzzBase = 0x10000000ULL;
constexpr std::size_t kReadableSize = 4096;
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) return 0;
    auto backend = std::make_shared<tessera::testing::FakeMemoryBackend>();
    backend->map_region(tessera::Address{kFuzzBase}, kReadableSize,
                        tessera::MemoryProtection::ReadWrite);
    backend->map_region(tessera::Address{kFuzzBase + kReadableSize}, kReadableSize,
                        tessera::MemoryProtection::NoAccess);
    const std::size_t copied = (std::min)(size, kReadableSize);
    if (copied != 0) {
        const std::span<const std::byte> bytes{
            reinterpret_cast<const std::byte*>(data), copied};
        backend->poke_bytes(tessera::Address{kFuzzBase}, bytes);
    }
    auto process = tessera::testing::FakeMemoryBackend::make_process(
        backend, tessera::Architecture::X64);
    const tessera::AddressRange image{tessera::Address{kFuzzBase}, 2u * kReadableSize};
    (void)tessera::rtti::PythonBridgeScanner::discover_all(process, image);
    return 0;
}
#if !defined(TESSERA_LIBFUZZER)
int main() {
    constexpr char sample[] = "builtins\0__main__\0PyObject\0PyTypeObject\0";
    return LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif
