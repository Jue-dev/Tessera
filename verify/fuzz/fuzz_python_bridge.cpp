#include "FakeMemoryBackend.hpp"

#include "fuzz_corpus_runner.hpp"
#include "tessera/rtti/python_bridge.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace {

constexpr std::uint64_t kFuzzBase = 0x10000000ULL;
constexpr std::size_t kPageSize = 4096;
constexpr std::size_t kMaxStringInput = 256;

void write_string(tessera::testing::FakeMemoryBackend& backend,
                  std::uint64_t offset,
                  std::string_view value) {
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(value.data()), value.size() + 1};
    backend.poke_bytes(tessera::Address{kFuzzBase + offset}, bytes);
}

void write_input_field(tessera::testing::FakeMemoryBackend& backend,
                       std::uint64_t destination,
                       const std::uint8_t* data,
                       std::size_t size,
                       std::size_t input_offset,
                       std::size_t field_size) {
    if (input_offset > size || field_size > size - input_offset) {
        return;
    }
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(data + input_offset), field_size};
    backend.poke_bytes(tessera::Address{kFuzzBase + destination}, bytes);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        return 0;
    }

    auto backend = std::make_shared<tessera::testing::FakeMemoryBackend>();
    backend->map_region(tessera::Address{kFuzzBase}, kPageSize,
                        tessera::MemoryProtection::ReadWrite);
    // The image crosses an unreadable page; executable candidates live after it.
    backend->map_region(tessera::Address{kFuzzBase + kPageSize}, kPageSize,
                        tessera::MemoryProtection::NoAccess);
    backend->map_region(tessera::Address{kFuzzBase + 2u * kPageSize}, kPageSize,
                        tessera::MemoryProtection::ExecuteRead);

    // A valid baseline PyMethodDef table and _inittab run. Fuzz bytes below
    // overwrite the actual fields consumed by scan_method_tables/scan_inittab.
    write_string(*backend, 0x500, "bridge_call");
    write_string(*backend, 0x700, "minimal Python bridge doc");
    write_string(*backend, 0x900, "bridge_mod");

    const auto pointer = [&](std::size_t offset, std::uint64_t value) {
        backend->poke_value(tessera::Address{kFuzzBase + offset}, value);
    };

    // Model one minimal 64-bit PyTypeObject and its three optional metadata
    // tables so the same harness exercises cyclic object/table references.
    constexpr std::size_t kTypeObjectOffset = 0xA00;
    constexpr std::size_t kTypeNameOffset = 0xB00;
    constexpr std::size_t kTypeMethodsOffset = 0xC00;
    constexpr std::size_t kTypeMembersOffset = 0xD00;
    constexpr std::size_t kTypeGetSetOffset = 0xE00;
    write_string(*backend, kTypeNameOffset, "bridge.Type");

    pointer(kTypeObjectOffset + 0u * 8u, 2u); // ob_refcnt
    pointer(kTypeObjectOffset + 2u * 8u, 0u); // ob_size
    pointer(kTypeObjectOffset + 3u * 8u, kFuzzBase + kTypeNameOffset); // tp_name
    pointer(kTypeObjectOffset + 4u * 8u, 16u); // tp_basicsize
    pointer(kTypeObjectOffset + 5u * 8u, 0u); // tp_itemsize
    pointer(kTypeObjectOffset + 29u * 8u, kFuzzBase + kTypeMethodsOffset); // tp_methods
    pointer(kTypeObjectOffset + 30u * 8u, kFuzzBase + kTypeMembersOffset); // tp_members
    pointer(kTypeObjectOffset + 31u * 8u, kFuzzBase + kTypeGetSetOffset); // tp_getset

    // PyMethodDef: {ml_name, ml_meth, ml_flags, pad, ml_doc}, followed by a
    // zero sentinel. The executable candidate remains in the RX page.
    pointer(kTypeMethodsOffset + 0u, kFuzzBase + 0x500);
    pointer(kTypeMethodsOffset + 8u, kFuzzBase + 2u * kPageSize);
    backend->poke_value(tessera::Address{kFuzzBase + kTypeMethodsOffset + 16u},
                        std::uint32_t{0x01});
    backend->poke_value(tessera::Address{kFuzzBase + kTypeMethodsOffset + 20u},
                        std::uint32_t{0});
    pointer(kTypeMethodsOffset + 24u, kFuzzBase + 0x700);

    // PyMemberDef: name, type, pad, offset, flags, pad, doc; then sentinel.
    pointer(kTypeMembersOffset + 0u, kFuzzBase + 0x500);
    backend->poke_value(tessera::Address{kFuzzBase + kTypeMembersOffset + 8u},
                        std::int32_t{1});
    backend->poke_value(tessera::Address{kFuzzBase + kTypeMembersOffset + 12u},
                        std::int32_t{0});
    pointer(kTypeMembersOffset + 16u, 8u);
    backend->poke_value(tessera::Address{kFuzzBase + kTypeMembersOffset + 24u},
                        std::int32_t{0});
    backend->poke_value(tessera::Address{kFuzzBase + kTypeMembersOffset + 28u},
                        std::int32_t{0});
    pointer(kTypeMembersOffset + 32u, kFuzzBase + 0x700);

    // PyGetSetDef: name, getter, setter, doc, closure; then sentinel.
    pointer(kTypeGetSetOffset + 0u, kFuzzBase + 0x500);
    pointer(kTypeGetSetOffset + 8u, kFuzzBase + 2u * kPageSize);
    pointer(kTypeGetSetOffset + 16u, 0u);
    pointer(kTypeGetSetOffset + 24u, kFuzzBase + 0x700);
    pointer(kTypeGetSetOffset + 32u, 0u);
    pointer(0x200, kFuzzBase + 0x500);        // PyMethodDef.ml_name
    pointer(0x208, kFuzzBase + 2u * kPageSize); // PyMethodDef.ml_meth
    backend->poke_value(tessera::Address{kFuzzBase + 0x210}, std::uint32_t{0x01});
    backend->poke_value(tessera::Address{kFuzzBase + 0x214}, std::uint32_t{0});
    pointer(0x218, kFuzzBase + 0x700);        // PyMethodDef.ml_doc
    // Zero-filled second record is the PyMethodDef sentinel.

    pointer(0x300, kFuzzBase + 0x900);        // _inittab.name
    pointer(0x308, kFuzzBase + 2u * kPageSize); // _inittab.initfunc
    // Zero-filled second record is the _inittab sentinel.

    // Each complete field is independently fuzzable. In particular, the
    // corpus can direct name/doc/init pointers into NoAccess or outside image.
    write_input_field(*backend, 0x200, data, size, 0, 8);
    write_input_field(*backend, 0x208, data, size, 8, 8);
    write_input_field(*backend, 0x210, data, size, 16, 4);
    write_input_field(*backend, 0x214, data, size, 20, 4);
    write_input_field(*backend, 0x218, data, size, 24, 8);
    write_input_field(*backend, 0x300, data, size, 32, 8);
    write_input_field(*backend, 0x308, data, size, 40, 8);

    // Extended inputs can mutate type/table references without changing the
    // original 48-byte PyMethodDef + _inittab corpus contract.
    write_input_field(*backend, kTypeObjectOffset + 3u * 8u, data, size, 48, 8);
    write_input_field(*backend, kTypeObjectOffset + 29u * 8u, data, size, 56, 8);
    write_input_field(*backend, kTypeObjectOffset + 30u * 8u, data, size, 64, 8);
    write_input_field(*backend, kTypeObjectOffset + 31u * 8u, data, size, 72, 8);
    write_input_field(*backend, kTypeMethodsOffset, data, size, 80, 8);
    write_input_field(*backend, kTypeMethodsOffset + 8u, data, size, 88, 8);
    write_input_field(*backend, kTypeMembersOffset, data, size, 96, 8);
    write_input_field(*backend, kTypeGetSetOffset, data, size, 104, 8);

    // Exercise bounded C-string reads after the extended pointer mutations.
    if (size > 112) {
        const std::size_t copied = (std::min)(size - 112, kMaxStringInput);
        const std::span<const std::byte> bytes{
            reinterpret_cast<const std::byte*>(data + 112), copied};
        backend->poke_bytes(tessera::Address{kFuzzBase + 0x500}, bytes);
        backend->poke_value(tessera::Address{kFuzzBase + 0x500 + copied}, std::byte{0});
    }

    auto process = tessera::testing::FakeMemoryBackend::make_process(
        backend, tessera::Architecture::X64);
    const tessera::AddressRange image{
        tessera::Address{kFuzzBase}, 3u * kPageSize};

    (void)tessera::rtti::PythonBridgeScanner::discover_all(process, image);
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main(int argc, char** argv) {
    if (argc > 1) {
        return tessera::fuzz::run_corpus(argc, argv, &LLVMFuzzerTestOneInput);
    }
    constexpr char sample[] = "valid Python method table and inittab seed";
    return LLVMFuzzerTestOneInput(
        reinterpret_cast<const std::uint8_t*>(sample), sizeof(sample) - 1);
}
#endif // !defined(TESSERA_LIBFUZZER)
