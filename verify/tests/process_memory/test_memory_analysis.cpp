#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/memory/memory.hpp"

TEST_CASE("read_scatter preserves request order and reports per-request partial failures",
          "[memory][scatter]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x730000}, 0x1000, MemoryProtection::ReadWrite);

    const std::array<std::byte, 16> source{
        std::byte{0},  std::byte{1},  std::byte{2},  std::byte{3},
        std::byte{4},  std::byte{5},  std::byte{6},  std::byte{7},
        std::byte{8},  std::byte{9},  std::byte{10}, std::byte{11},
        std::byte{12}, std::byte{13}, std::byte{14}, std::byte{15}};
    backend->poke_bytes(Address{0x730100}, source);
    auto process = FakeMemoryBackend::make_process(backend);

    const std::array<MemoryReadRequest, 3> requests{{
        {Address{0x730108}, 3},
        {Address{0x730100}, 4},
        {Address{0x740000}, 2},
    }};
    auto results = read_scatter(process, requests, 4096, 8192);
    REQUIRE(results);
    REQUIRE(results->size() == 3);

    const std::vector<std::byte> expected_first{source[8], source[9], source[10]};
    const std::vector<std::byte> expected_second{source[0], source[1], source[2], source[3]};
    REQUIRE((*results)[0].succeeded());
    REQUIRE((*results)[0].bytes == expected_first);
    REQUIRE((*results)[1].succeeded());
    REQUIRE((*results)[1].bytes == expected_second);
    REQUIRE_FALSE((*results)[2].succeeded());
    REQUIRE((*results)[2].error->code == ErrorCode::AccessDenied);
}

TEST_CASE("MemorySnapshot captures a range and diff groups adjacent byte changes",
          "[memory][snapshot]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x750000}, 0x1000, MemoryProtection::ReadWrite);

    const std::array<std::byte, 8> first{
        std::byte{0}, std::byte{1}, std::byte{2}, std::byte{3},
        std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}};
    backend->poke_bytes(Address{0x750100}, first);
    auto process = FakeMemoryBackend::make_process(backend);

    auto before = MemorySnapshot::capture(process, {Address{0x750100}, 8});
    REQUIRE(before);

    const std::array<std::byte, 8> second{
        std::byte{0}, std::byte{1}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{4}, std::byte{0xcc}, std::byte{6}, std::byte{7}};
    backend->poke_bytes(Address{0x750100}, second);
    auto after = MemorySnapshot::capture(process, {Address{0x750100}, 8});
    REQUIRE(after);

    auto changes = diff(*before, *after);
    REQUIRE(changes);
    REQUIRE(changes->size() == 2);
    REQUIRE((*changes)[0].offset == 2);
    REQUIRE((*changes)[0].old_bytes.size() == 2);
    REQUIRE((*changes)[0].new_bytes[0] == std::byte{0xaa});
    REQUIRE((*changes)[1].offset == 5);
    REQUIRE((*changes)[1].old_bytes.size() == 1);
}
