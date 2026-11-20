#include "FakeMemoryBackend.hpp"
#include "tessera/rtti/python_bridge.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace {

constexpr std::uint64_t kFuzzBase = 0x10000000ULL;
constexpr std::size_t kPageSize = 4096;
constexpr std::size_t kFuzzOffset = 0x800;
constexpr std::size_t kMaxFuzzBytes = kPageSize - kFuzzOffset;

void write_string(tessera::testing::FakeMemoryBackend& backend,
                  std::uint64_t offset,
                  std::string_view value) {
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(value.data()), value.size() + 1};
    backend.poke_bytes(tessera::Address{kFuzzBase + offset}, bytes);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        return 0;
    }

    auto backend = std::make_shared<tessera::testing::FakeMemoryBackend>();
    backend->map_region(tessera::Address{kFuzzBase}, kPageSize,
                        tessera::MemoryProtection::ReadWrite);
    // The module range crosses a deliberately unreadable page boundary.
    backend->map_region(tessera::Address{kFuzzBase + kPageSize}, kPageSize,
                        tessera::MemoryProtection::NoAccess);
    backend->map_region(tessera::Address{kFuzzBase + 2u * kPageSize}, kPageSize,
                        tessera::MemoryProtection::ExecuteRead);

    // Keep a small valid CPython-style image in the readable page so every
    // input reaches successful table/type candidates as well as malformed data.
    write_string(*backend, 0x100, "bridge_call");
    write_string(*backend, 0x120, "minimal Python bridge seed");
    write_string(*backend, 0x160, "bridge_mod");
    write_string(*backend, 0x180, "demo.Widget");

    const auto pointer = [&](std::size_t offset, std::uint64_t value) {
        backend->poke_value(tessera::Address{kFuzzBase + offset}, value);
    };
    pointer(0x200, kFuzzBase + 0x100);       // PyMethodDef.ml_name
    pointer(0x208, kFuzzBase + 2u * kPageSize); // PyMethodDef.ml_meth (executable)
    backend->poke_value(tessera::Address{kFuzzBase + 0x210}, std::uint32_t{0x01});
    backend->poke_value(tessera::Address{kFuzzBase + 0x214}, std::uint32_t{0});
    pointer(0x218, kFuzzBase + 0x120);       // PyMethodDef.ml_doc
    // The zero-filled second record is the PyMethodDef sentinel.

    pointer(0x300, kFuzzBase + 0x160);       // _inittab.name
    pointer(0x308, kFuzzBase + 2u * kPageSize); // _inittab.initfunc
    // The zero-filled second record is the _inittab sentinel.

    // A bounded PyTypeObject prefix with a valid in-image tp_name.
    pointer(0x400, 1);                       // ob_refcnt
    pointer(0x410, 0);                       // ob_size
    pointer(0x418, kFuzzBase + 0x180);       // tp_name
    pointer(0x420, 64);                      // tp_basicsize
    pointer(0x428, 0);                       // tp_itemsize

    const std::size_t copied = (std::min)(size, kMaxFuzzBytes);
    if (copied != 0) {
        const std::span<const std::byte> bytes{
            reinterpret_cast<const std::byte*>(data), copied};
        backend->poke_bytes(tessera::Address{kFuzzBase + kFuzzOffset}, bytes);
    }

    auto process = tessera::testing::FakeMemoryBackend::make_process(
        backend, tessera::Architecture::X64);
    const tessera::AddressRange image{
        tessera::Address{kFuzzBase}, 3u * kPageSize};

    (void)tessera::rtti::PythonBridgeScanner::discover_all(process, image);
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main() {
    constexpr char sample[] = "invalid PyObject/PyTypeObject pointers, cycles, oversized lengths";
    return LLVMFuzzerTestOneInput(
        reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif // !defined(TESSERA_LIBFUZZER)
