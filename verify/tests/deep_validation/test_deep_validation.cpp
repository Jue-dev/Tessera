#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <span>
#include <string>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/json/json.hpp"
#include "tessera/module/pe_image.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/scanner/scanner.hpp"

namespace {
std::vector<std::byte> read_binary(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    in.seekg(0, std::ios::end);
    const auto n = in.tellg();
    if (n < 0) return {};
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> bytes(static_cast<std::size_t>(n));
    if (!bytes.empty()) in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in && !bytes.empty()) return {};
    return bytes;
}
}

TEST_CASE("Deep validation: scanner agrees with independent byte-search oracle",
          "[deep][scanner][property]") {
    using namespace tessera;
    using namespace tessera::testing;

    std::mt19937_64 rng{0x5445535345524131ULL};
    constexpr std::uint64_t base = 0x72000000ULL;
    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& region = backend->map_region(Address{base}, 0x4000, MemoryProtection::Read);
    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64);
    Scanner scanner{proc};

    for (std::size_t round = 0; round < 160; ++round) {
        for (auto& byte : region.storage) byte = static_cast<std::byte>(rng() & 0xFFu);
        const std::size_t needle_len = 2 + static_cast<std::size_t>(rng() % 14);
        std::vector<std::byte> needle(needle_len);
        for (auto& byte : needle) byte = static_cast<std::byte>(rng() & 0xFFu);

        // Plant zero to four occurrences, including chunk boundaries and adjacent candidates.
        const std::size_t planted = static_cast<std::size_t>(rng() % 5);
        for (std::size_t i = 0; i < planted; ++i) {
            const std::size_t pos = (i == 0) ? (0x100 + (round % 7) * 31)
                                              : static_cast<std::size_t>(rng() % (region.storage.size() - needle_len));
            std::copy(needle.begin(), needle.end(), region.storage.begin() + static_cast<std::ptrdiff_t>(pos));
        }

        std::vector<Address> expected;
        for (std::size_t pos = 0; pos + needle_len <= region.storage.size(); ++pos) {
            if (std::equal(needle.begin(), needle.end(), region.storage.begin() + static_cast<std::ptrdiff_t>(pos)))
                expected.emplace_back(base + pos);
        }
        auto pattern = Pattern::from_bytes(needle);
        REQUIRE(pattern.has_value());
        ScanOptions options{};
        options.chunk_size = 17 + static_cast<std::size_t>(rng() % 97);
        const auto actual = scanner.scan(AddressRange{Address{base}, region.storage.size()}, *pattern, options);
        REQUIRE(actual.has_value());
        REQUIRE(actual->hits == expected);
        REQUIRE_FALSE(actual->cancelled);
        REQUIRE(actual->stats.bytes_scanned == region.storage.size());
    }
}

TEST_CASE("Deep validation: JSON parser survives deterministic malformed-input fuzzing and round trips",
          "[deep][json][fuzz]") {
    using namespace tessera::json;
    std::mt19937_64 rng{0x4A534F4E5F46555AULL};

    for (std::size_t i = 0; i < 12000; ++i) {
        const std::size_t n = static_cast<std::size_t>(rng() % 512);
        std::string raw(n, '\0');
        for (char& ch : raw) ch = static_cast<char>(rng() & 0xFFu);
        JsonParseError error{};
        auto parsed = parse(raw, JsonParseOptions{.max_depth = 32, .max_bytes = 1024}, &error);
        if (parsed) {
            auto encoded = write(*parsed, JsonWriteOptions{.pretty = false});
            REQUIRE(encoded.has_value());
            auto reparsed = parse(*encoded, JsonParseOptions{.max_depth = 32, .max_bytes = 1024});
            REQUIRE(reparsed.has_value());
            auto encoded_again = write(*reparsed, JsonWriteOptions{.pretty = false});
            REQUIRE(encoded_again.has_value());
            REQUIRE(*encoded_again == *encoded);
        } else {
            REQUIRE(error.code != JsonErrorCode::None);
            REQUIRE(error.byte_offset <= raw.size());
        }
    }

    // Valid generated values cover escaping, signed/unsigned numeric limits and nesting.
    for (std::size_t i = 0; i < 1000; ++i) {
        JsonValue obj = JsonValue::make_object();
        obj.set("index", JsonValue{static_cast<std::uint64_t>(rng())});
        obj.set("signed", JsonValue{static_cast<std::int64_t>(rng())});
        obj.set("truth", JsonValue{(rng() & 1u) != 0});
        obj.set("payload", JsonValue{std::string("tessera\n\t\"\\\xF0\x9F\x9A\x80")});
        JsonValue arr = JsonValue::make_array();
        for (int j = 0; j < 6; ++j) arr.push_back(JsonValue{static_cast<std::int64_t>(rng())});
        obj.set("values", std::move(arr));
        auto text = write(obj, JsonWriteOptions{.pretty = (i % 2) == 0});
        REQUIRE(text.has_value());
        auto back = parse(*text);
        REQUIRE(back.has_value());
        auto text_again = write(*back, JsonWriteOptions{.pretty = (i % 2) == 0});
        REQUIRE(text_again.has_value());
        REQUIRE(*text_again == *text);
    }
}

TEST_CASE("Deep validation: PE parser handles truncation and deterministic header mutations",
          "[deep][pe][fuzz]") {
#ifndef TESSERA_TEST_FIXTURE_DIR
    SUCCEED("PE mutation fixture directory is not configured");
#else
    const auto path = std::filesystem::path{TESSERA_TEST_FIXTURE_DIR} / "rtti_fixture_x64.dll";
    const auto original = read_binary(path);
    REQUIRE(original.size() > 1024);
    auto image = tessera::PeImage::from_raw_bytes(original);
    REQUIRE(image.has_value());
    REQUIRE(image->kind() == tessera::PeKind::Pe32Plus);
    auto image_from_file = tessera::PeImage::from_file(path);
    REQUIRE(image_from_file.has_value());
    REQUIRE(image_from_file->kind() == tessera::PeKind::Pe32Plus);

    const auto x86_path = std::filesystem::path{TESSERA_TEST_FIXTURE_DIR} / "rtti_fixture_x86.dll";
    const auto x86_bytes = read_binary(x86_path);
    REQUIRE(x86_bytes.size() > 1024);
    auto x86_image = tessera::PeImage::from_raw_bytes(x86_bytes);
    REQUIRE(x86_image.has_value());
    REQUIRE(x86_image->kind() == tessera::PeKind::Pe32);
    REQUIRE_FALSE(image->sections().empty());

    // Truncated inputs are either cleanly rejected or remain safe to query.
    for (std::size_t n = 0; n < original.size(); n += 13) {
        auto truncated = tessera::PeImage::from_raw_bytes(std::span<const std::byte>{original}.first(n));
        if (truncated) {
            (void)truncated->sections();
            (void)truncated->exports();
            (void)truncated->imports();
            (void)truncated->exception_functions();
            (void)truncated->code_view();
        }
    }

    std::mt19937_64 rng{0x50455F4D55544154ULL};
    for (std::size_t i = 0; i < 3000; ++i) {
        auto mutated = original;
        const std::size_t changes = 1 + static_cast<std::size_t>(rng() % 8);
        for (std::size_t j = 0; j < changes; ++j) {
            const std::size_t pos = static_cast<std::size_t>(rng() % mutated.size());
            mutated[pos] = static_cast<std::byte>(rng() & 0xFFu);
        }
        auto candidate = tessera::PeImage::from_raw_bytes(mutated);
        if (candidate) {
            (void)candidate->find_section(".text");
            (void)candidate->find_export("sum_plain");
            (void)candidate->imports();
            (void)candidate->exception_functions();
        }
    }
#endif
}



TEST_CASE("Deep validation: MSVC ABI preserves branching virtual-base flags in x86/x64 PE fixtures",
          "[deep][rtti][regression]") {
#ifndef TESSERA_TEST_FIXTURE_DIR
    SUCCEED("PE RTTI fixture directory is not configured");
#else
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::testing;

    const auto validate_fixture = [](const char* filename, Architecture architecture,
                                     PeKind expected_kind) {
        const auto path = std::filesystem::path{TESSERA_TEST_FIXTURE_DIR} / filename;
        const auto bytes = read_binary(path);
        REQUIRE(bytes.size() > 1024);
        const auto image = PeImage::from_raw_bytes(bytes);
        REQUIRE(image.has_value());
        REQUIRE(image->kind() == expected_kind);

        const Address image_base{image->image_base()};
        auto backend = std::make_shared<FakeMemoryBackend>();
        auto& headers = backend->map_region(image_base, 0x400, MemoryProtection::Read);
        std::memcpy(headers.storage.data(), bytes.data(),
                    (std::min)(headers.storage.size(), bytes.size()));

        for (const auto& section : image->sections()) {
            const auto protection = section.is_executable()
                                        ? MemoryProtection::ExecuteRead
                                        : (section.is_writable() ? MemoryProtection::ReadWrite
                                                                 : MemoryProtection::Read);
            auto& region = backend->map_region(
                Address{image_base.value() + section.rva.value()}, section.effective_size(), protection);
            const auto copy_size = (std::min)(static_cast<std::size_t>(section.raw_size),
                                               region.storage.size());
            REQUIRE(section.raw_offset <= bytes.size());
            REQUIRE(copy_size <= bytes.size() - section.raw_offset);
            if (copy_size != 0) {
                std::memcpy(region.storage.data(), bytes.data() + section.raw_offset, copy_size);
            }
        }

        Process process = FakeMemoryBackend::make_process(backend, architecture);
        const AddressRange range{image_base, image->size_of_image()};
        const auto loaded_image = PeImage::from_memory(process, image_base);
        REQUIRE(loaded_image.has_value());
        const auto catalog = RttiCatalog::discover_all(process, range, &*loaded_image);
        REQUIRE(catalog.has_value());
        const auto diamond = catalog->find_class("VDiamond");
        REQUIRE(diamond.has_value());
        REQUIRE(diamond->base_classes.size() == 4);
        REQUIRE(diamond->is_multiple_inheritance());
        REQUIRE(diamond->has_virtual_branching_hierarchy());
        REQUIRE(diamond->has_virtual_base_classes());
        REQUIRE(diamond->is_virtual_inheritance());

        bool virtual_base_pmd_found = false;
        for (const auto& base : diamond->base_classes) {
            if (base.is_virtual_base()) virtual_base_pmd_found = true;
        }
        REQUIRE(virtual_base_pmd_found);
    };

    validate_fixture("rtti_virtual_branch_x64.dll", Architecture::X64, PeKind::Pe32Plus);
    validate_fixture("rtti_virtual_branch_x86.dll", Architecture::X86, PeKind::Pe32);
#endif
}

TEST_CASE("Deep validation: struct reconstruction follows a this-pointer stack spill",
          "[deep][rtti][regression]") {
#ifndef TESSERA_TEST_FIXTURE_DIR
    SUCCEED("PE regression fixture directory is not configured");
#else
    using namespace tessera;
    using namespace tessera::rtti;
    using namespace tessera::testing;

    const auto path = std::filesystem::path{TESSERA_TEST_FIXTURE_DIR} / "rtti_fixture_x64.dll";
    const auto file_bytes = read_binary(path);
    REQUIRE(file_bytes.size() > 1024);
    auto image = PeImage::from_raw_bytes(file_bytes);
    REQUIRE(image.has_value());
    REQUIRE(image->kind() == PeKind::Pe32Plus);

    const Address image_base{image->image_base()};
    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& headers = backend->map_region(image_base, 0x400, MemoryProtection::Read);
    std::memcpy(headers.storage.data(), file_bytes.data(),
                (std::min)(headers.storage.size(), file_bytes.size()));

    for (const auto& section : image->sections()) {
        const auto protection = section.is_executable()
                                    ? MemoryProtection::ExecuteRead
                                    : (section.is_writable() ? MemoryProtection::ReadWrite
                                                             : MemoryProtection::Read);
        auto& region = backend->map_region(
            Address{image_base.value() + section.rva.value()}, section.effective_size(), protection);
        const std::size_t copy_size = (std::min)(static_cast<std::size_t>(section.raw_size),
                                                 region.storage.size());
        const std::size_t raw_offset = section.raw_offset;
        REQUIRE(raw_offset <= file_bytes.size());
        REQUIRE(copy_size <= file_bytes.size() - raw_offset);
        if (copy_size != 0) {
            std::memcpy(region.storage.data(), file_bytes.data() + raw_offset, copy_size);
        }
    }

    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    const AddressRange image_range{image_base, image->size_of_image()};
    auto mapped_image = PeImage::from_memory(process, image_base);
    REQUIRE(mapped_image.has_value());

    auto function_list = BinaryExplorer::discover_functions(process, image_range, &*mapped_image);
    REQUIRE(function_list.has_value());
    auto exported = mapped_image->find_export("sum_plain");
    REQUIRE(exported.has_value());
    const auto function = std::find_if(function_list->begin(), function_list->end(),
                                       [&](const auto& item) {
                                           return item.address == exported->address;
                                       });
    REQUIRE(function != function_list->end());

    auto reconstructed = BinaryExplorer::reconstruct_struct(
        process, AddressRange{function->address, function->size}, "PlainFromMachineCode");
    REQUIRE(reconstructed.has_value());
    const bool field_10 = std::any_of(reconstructed->fields.begin(), reconstructed->fields.end(),
                                      [](const auto& field) { return field.offset == 0x10; });
    const bool field_14 = std::any_of(reconstructed->fields.begin(), reconstructed->fields.end(),
                                      [](const auto& field) { return field.offset == 0x14; });
    REQUIRE(field_10);
    REQUIRE(field_14);
#endif
}

TEST_CASE("Deep validation: pattern parser fuzzes malformed and valid token combinations",
          "[deep][pattern][fuzz]") {
    constexpr std::uint64_t seed = 0x5041545445524EULL;
    std::seed_seq seed_words{static_cast<std::uint32_t>(seed),
                             static_cast<std::uint32_t>(seed >> 32U)};
    std::mt19937 rng{seed_words};
    constexpr char alphabet[] = "0123456789ABCDEFabcdef? xyz!";
    for (std::size_t i = 0; i < 15000; ++i) {
        std::string text;
        const std::size_t tokens = 1 + (rng() % 24);
        for (std::size_t j = 0; j < tokens; ++j) {
            if (j) text.push_back((rng() & 3u) ? ' ' : '\t');
            const std::size_t len = 1 + (rng() % 4);
            for (std::size_t k = 0; k < len; ++k)
                text.push_back(alphabet[rng() % (sizeof(alphabet) - 1)]);
        }
        tessera::PatternError error{};
        auto pattern = tessera::Pattern::parse(text, &error);
        if (pattern) {
            REQUIRE(pattern->size() > 0);
            REQUIRE(pattern->size() <= tessera::Pattern::kMaxPatternLength);
            REQUIRE(pattern->bytes().size() == pattern->mask().size());
            for (const auto mask : pattern->mask()) {
                REQUIRE(mask == std::byte{0} || mask == std::byte{0x0F} ||
                        mask == std::byte{0xF0} || mask == std::byte{0xFF});
            }
        } else {
            REQUIRE(!error.reason.empty());
        }
    }
}
