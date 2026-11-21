#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <optional>
#include <string>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/rtti/object_view.hpp"
#include "tessera/rtti/python_bridge.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/targets/target_profile_json.hpp"
#include "tessera/targets/target_runtime.hpp"

#include "rtti_test_helpers.hpp"

using namespace rtti_test_support;

TEST_CASE("RTTI distinguishes virtual bases from the CHD virtual-branching bit", "[rtti]") {
    using namespace tessera::rtti;

    RttiClassDescriptor simple_virtual{};
    RttiBaseEntry virtual_base{};
    virtual_base.pmd = MsvcPmd{.mdisp = 0, .pdisp = 0, .vdisp = 4};
    simple_virtual.base_classes.push_back(virtual_base);

    REQUIRE(simple_virtual.has_virtual_base_classes());
    REQUIRE(simple_virtual.is_virtual_inheritance());
    REQUIRE_FALSE(simple_virtual.has_virtual_branching_hierarchy());

    RttiClassDescriptor branching_virtual{};
    branching_virtual.chd_attributes = 0x02u;

    REQUIRE_FALSE(branching_virtual.has_virtual_base_classes());
    REQUIRE(branching_virtual.has_virtual_branching_hierarchy());
    REQUIRE(branching_virtual.is_virtual_inheritance());
}

TEST_CASE("MSVC RTTI symbol demangling and non-virtual reflection / ObjectView", "[rtti][reflection]") {
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::reflection;

    REQUIRE(demangle_msvc_symbol(".?AVPlayer@Game@Engine@@") == "Engine::Game::Player");
    REQUIRE(demangle_msvc_symbol(".?AUVec3@Math@@") == "Math::Vec3");
    REQUIRE(demangle_msvc_symbol(".?AW4AIState@AI@@") == "AI::AIState");
    REQUIRE(demangle_msvc_symbol(".?AV?$Vector@M@Math@@") == "Math::Vector<float>");

    enum class WeaponState : std::int32_t {
        Idle = 0,
        Firing = 1,
        Reloading = 2,
    };

    auto enum_type = EnumBuilder<WeaponState>("Game::WeaponState")
                         .value("Idle", WeaponState::Idle)
                         .value("Firing", WeaponState::Firing)
                         .value("Reloading", WeaponState::Reloading)
                         .build();
    REQUIRE(enum_type.kind == TypeKind::Enum);
    REQUIRE(enum_type.enum_info.has_value());
    REQUIRE(enum_type.enum_info->find_by_name("Reloading")->value == 2);
    REQUIRE(enum_type.enum_info->find_by_value(1)->name == "Firing");

    struct NonVirtualTransform {
        float x;
        float y;
        std::uint32_t flags;
    };

    auto transform_type =
        TypeBuilder<NonVirtualTransform>("Math::NonVirtualTransform")
            .field("x", TypeId::from_name("float"), 0, 4)
            .field("y", TypeId::from_name("float"), 4, 4)
            .bitfield("is_active", TypeId::from_name("uint32"), 8, 4, 0, 1)
            .bitfield("layer_id", TypeId::from_name("uint32"), 8, 4, 4, 4)
            .non_virtual_method("UpdateTransform", Rva{0x1200})
            .build();

    auto backend = std::make_shared<testing::FakeMemoryBackend>();
    auto& data_reg = backend->map_region(Address{0x200000}, 0x1000, MemoryProtection::ReadWrite);
    write_f32(data_reg.storage, 0x100 + 0, 42.5f);
    write_f32(data_reg.storage, 0x100 + 4, -18.25f);
    write_u32(data_reg.storage, 0x100 + 8, (1u << 0) | (7u << 4));

    Process proc = testing::FakeMemoryBackend::make_process(backend, Architecture::X64);
    ObjectView view{proc, Address{0x200100}, transform_type};

    REQUIRE(*view.read_field<float>("x") == 42.5f);
    REQUIRE(*view.read_field<float>("y") == -18.25f);
    REQUIRE(*view.read_bitfield("is_active") == 1ULL);
    REQUIRE(*view.read_bitfield("layer_id") == 7ULL);

    REQUIRE(view.write_field<float>("x", 99.0f).has_value());
    REQUIRE(*view.read_field<float>("x") == 99.0f);
    REQUIRE(*view.resolve_method("UpdateTransform", Address{0x140000000ULL}) ==
            Address{0x140001200ULL});
}


TEST_CASE("RTTI parses x86 absolute-VA and x64 RVA layouts and rejects malformed bounds", "[rtti][layout]") {
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::testing;

    const auto make_image = [](Architecture architecture) {
        constexpr std::uint64_t base = 0x10000000ULL;
        const bool x64 = architecture == Architecture::X64;
        const std::size_t pointer_size = x64 ? 8u : 4u;
        std::vector<std::byte> image(0x300, std::byte{0});
        const auto write_pointer = [&](std::size_t offset, std::uint64_t value) {
            if (x64) {
                write_u64(image, offset, value);
            } else {
                write_u32(image, offset, static_cast<std::uint32_t>(value));
            }
        };
        const auto image_reference = [&](std::uint32_t rva) -> std::uint32_t {
            return x64 ? rva : static_cast<std::uint32_t>(base + rva);
        };

        write_pointer(0x40, base + 0x280);
        write_pointer(0x40 + pointer_size, 0);
        write_cstr(image, 0x40 + pointer_size * 2u, ".?AVDerived@Tessera@@");
        write_pointer(0x240, base + 0x280);
        write_pointer(0x240 + pointer_size, 0);
        write_cstr(image, 0x240 + pointer_size * 2u, ".?AVBase@Tessera@@");

        write_u32(image, 0x90, 0);
        write_u32(image, 0x94, 0x03u); // Multiple-inheritance and virtual-branching flags.
        write_u32(image, 0x98, 2);
        write_u32(image, 0x9C, image_reference(0xB0));
        write_u32(image, 0xB0, image_reference(0xC0));
        write_u32(image, 0xB4, image_reference(0xE0));

        write_u32(image, 0xC0, image_reference(0x40));
        write_u32(image, 0xC4, 0);
        write_i32(image, 0xC8, 0);
        write_i32(image, 0xCC, -1);
        write_i32(image, 0xD0, 0);
        write_u32(image, 0xD4, 0);
        write_u32(image, 0xD8, 0);

        write_u32(image, 0xE0, image_reference(0x240));
        write_u32(image, 0xE4, 0);
        write_i32(image, 0xE8, -8);
        write_i32(image, 0xEC, 4);
        write_i32(image, 0xF0, 12);
        write_u32(image, 0xF4, 0);
        write_u32(image, 0xF8, 0);

        write_u32(image, 0x100, x64 ? 1u : 0u);
        write_u32(image, 0x104, 8);
        write_u32(image, 0x108, 4);
        write_u32(image, 0x10C, image_reference(0x40));
        write_u32(image, 0x110, image_reference(0x90));
        if (x64) {
            write_u32(image, 0x114, 0x100);
        }

        write_pointer(0x180, base + 0x100); // vftable[-1] -> CompleteObjectLocator
        write_pointer(0x180 + pointer_size, base + 0x200);
        return image;
    };

    for (const Architecture architecture : {Architecture::X86, Architecture::X64}) {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto backend = std::make_shared<FakeMemoryBackend>();
        auto image = make_image(architecture);
        backend->map_region(Address{base}, image.size(), MemoryProtection::ExecuteReadWrite);
        backend->poke_bytes(Address{base}, image);
        auto process = FakeMemoryBackend::make_process(backend, architecture);
        const AddressRange range{Address{base}, image.size()};

        auto catalog = RttiCatalog::discover_all(process, range);
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().size() == 1);
        const auto& cls = catalog->classes().front();
        REQUIRE(cls.mangled_name == ".?AVDerived@Tessera@@");
        REQUIRE(cls.offset == 8);
        REQUIRE(cls.cd_offset == 4);
        REQUIRE(cls.virtual_methods.size() == 1);
        REQUIRE(cls.base_classes.size() == 1);
        REQUIRE(cls.is_multiple_inheritance());
        REQUIRE(cls.has_virtual_branching_hierarchy());
        REQUIRE(cls.has_virtual_base_classes());
        REQUIRE(cls.is_virtual_inheritance());
        REQUIRE(cls.base_classes.front().is_virtual_base());
        REQUIRE(cls.base_classes.front().pmd.mdisp == -8);
        REQUIRE(cls.base_classes.front().pmd.pdisp == 4);
        REQUIRE(cls.base_classes.front().pmd.vdisp == 12);
    }

    // Corrupt x86 absolute-VA COL references and x64 COL signature values.
    for (const Architecture architecture : {Architecture::X86, Architecture::X64}) {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto image = make_image(architecture);
        const bool x64 = architecture == Architecture::X64;
        write_u32(image, 0x100, x64 ? 0u : 1u);
        if (!x64) {
            write_u32(image, 0x10C, 0xF0000000u);
        }
        auto backend = std::make_shared<FakeMemoryBackend>();
        backend->map_region(Address{base}, image.size(), MemoryProtection::ExecuteReadWrite);
        backend->poke_bytes(Address{base}, image);
        auto process = FakeMemoryBackend::make_process(backend, architecture);
        auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, image.size()});
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().empty());
    }

    // An unaligned COL is not accepted by the four-byte structure sweep.
    {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto image = make_image(Architecture::X86);
        std::array<std::byte, 20> col{};
        std::memcpy(col.data(), image.data() + 0x100, col.size());
        std::fill(image.begin() + 0x100, image.begin() + 0x114, std::byte{0});
        std::memcpy(image.data() + 0x102, col.data(), col.size());
        write_u32(image, 0x180, static_cast<std::uint32_t>(base + 0x102));
        auto backend = std::make_shared<FakeMemoryBackend>();
        backend->map_region(Address{base}, image.size(), MemoryProtection::ExecuteReadWrite);
        backend->poke_bytes(Address{base}, image);
        auto process = FakeMemoryBackend::make_process(backend, Architecture::X86);
        auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, image.size()});
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().empty());
    }

    // Truncated COL/CHD/BCA data and unreadable backing memory fail closed.
    {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto full_image = make_image(Architecture::X86);
        auto backend = std::make_shared<FakeMemoryBackend>();
        backend->map_region(Address{base}, 0x110, MemoryProtection::ExecuteReadWrite);
        backend->poke_bytes(Address{base}, std::span<const std::byte>{full_image}.first(0x110));
        auto process = FakeMemoryBackend::make_process(backend, Architecture::X86);
        auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, 0x110});
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().empty());
        auto inspected = RttiCatalog::inspect_vftable(process, AddressRange{Address{base}, 0x110},
                                                      Address{base + 0x184});
        REQUIRE_FALSE(inspected.has_value());
    }
    {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto backend = std::make_shared<FakeMemoryBackend>();
        auto& region = backend->map_region(Address{base}, 0x300, MemoryProtection::ExecuteReadWrite);
        const auto image = make_image(Architecture::X86);
        backend->poke_bytes(Address{base}, image);
        region.readable_prefix_limit = 0x80;
        auto process = FakeMemoryBackend::make_process(backend, Architecture::X86);
        auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, 0x300});
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().empty());
    }


    // A TypeDescriptor name that starts inside the range but is truncated before its terminator.
    {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto image = make_image(Architecture::X86);
        auto backend = std::make_shared<FakeMemoryBackend>();
        backend->map_region(Address{base}, 0x50, MemoryProtection::ExecuteReadWrite);
        backend->poke_bytes(Address{base}, std::span<const std::byte>{image}.first(0x50));
        auto process = FakeMemoryBackend::make_process(backend, Architecture::X86);
        auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, 0x50});
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().empty());
    }

    // An invalid BaseClassArray VA is ignored while a valid COL and vftable remain discoverable.
    {
        constexpr std::uint64_t base = 0x10000000ULL;
        auto image = make_image(Architecture::X86);
        write_u32(image, 0x9C, 0xF0000000u);
        auto backend = std::make_shared<FakeMemoryBackend>();
        backend->map_region(Address{base}, image.size(), MemoryProtection::ExecuteReadWrite);
        backend->poke_bytes(Address{base}, image);
        auto process = FakeMemoryBackend::make_process(backend, Architecture::X86);
        auto catalog = RttiCatalog::discover_all(process, AddressRange{Address{base}, image.size()});
        REQUIRE(catalog.has_value());
        REQUIRE(catalog->classes().size() == 1);
        REQUIRE(catalog->classes().front().base_classes.empty());
        REQUIRE(catalog->classes().front().virtual_methods.size() == 1);
    }
    // Checked range-end arithmetic rejects a range that wraps uint64_t.
    {
        auto backend = std::make_shared<FakeMemoryBackend>();
        auto process = FakeMemoryBackend::make_process(backend, Architecture::X64);
        const AddressRange overflow_range{Address{0xFFFFFFFFFFFFFFF0ULL}, 0x40};
        REQUIRE_FALSE(RttiCatalog::discover_all(process, overflow_range).has_value());
    }
}


TEST_CASE("RTTI discovery rejects empty, truncated, and unreadable input ranges", "[rtti][negative]") {
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x310000}, 0x100, MemoryProtection::ReadWrite);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);

    REQUIRE_FALSE(BinaryExplorer::scan_all_type_descriptors(
        process, AddressRange{Address{0x310000}, 0}).has_value());
    const auto truncated = BinaryExplorer::scan_all_type_descriptors(
        process, AddressRange{Address{0x310000}, 0x1000});
    REQUIRE_FALSE(truncated.has_value());

    auto unreadable = std::make_shared<FakeMemoryBackend>();
    unreadable->map_region(Address{0x320000}, 0x100, MemoryProtection::None);
    Process unreadable_process = FakeMemoryBackend::make_process(unreadable, Architecture::X86);
    const auto result = BinaryExplorer::scan_all_type_descriptors(
        unreadable_process, AddressRange{Address{0x320000}, 0x100});
    REQUIRE(result.has_value());
    REQUIRE(result->empty());
}

TEST_CASE("RTTI object view rejects out-of-range field layouts", "[rtti][negative]") {
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::reflection;
    using namespace tessera::testing;

    struct SmallObject { std::uint32_t value; };
    auto type = TypeBuilder<SmallObject>("SmallObject")
        .field("value", TypeId::from_name("uint32"), 0, 4)
        .build();
    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x330000}, 0x100, MemoryProtection::ReadWrite);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X86);
    ObjectView view{process, Address{0x3300FE}, type};
    REQUIRE_FALSE(view.read_field<std::uint32_t>("value").has_value());
}
