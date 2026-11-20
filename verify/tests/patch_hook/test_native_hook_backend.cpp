#include "patch_hook_test_support.hpp"

TEST_CASE("Native inline short tail jumps do not extend the stolen block to their targets",
          "[hook][native][relocation][terminal]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // The tail jump's destination lies outside the five-byte entry patch.
    // The intervening bytes are padding and the target instruction is retained
    // in place rather than needlessly copied into the trampoline.
    code[64] = std::byte{0xEB};
    code[65] = std::byte{0x0A};
    code[76] = std::byte{0xB8};
    const std::uint32_t return_value = 42;
    std::memcpy(code + 77, &return_value, sizeof(return_value));
    code[81] = std::byte{0xC3};

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    REQUIRE(code[64] == std::byte{0xE9});
    REQUIRE(code[69] == std::byte{0x90});
    REQUIRE(code[76] == std::byte{0xB8});
    REQUIRE(hook->original()(7) == 42);
    REQUIRE(hook->remove().has_value());
    REQUIRE(code[64] == std::byte{0xEB});
    REQUIRE(code[76] == std::byte{0xB8});
}

TEST_CASE("Native inline backend accepts only safe padding after terminal prologue instructions",
          "[hook][native][compatibility][terminal]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // A RET followed by four one-byte NOPs is a complete five-byte patch
    // window: the trampoline retains the RET and the padding is never executed.
    code[64] = std::byte{0xC3};
    code[65] = std::byte{0x90};
    code[66] = std::byte{0x90};
    code[67] = std::byte{0x90};
    code[68] = std::byte{0x90};

    // A RET followed by MOV-immediate data is not a relocatable prologue.
    code[256] = std::byte{0xC3};
    code[257] = std::byte{0xB8};
    code[258] = std::byte{0x2A};
    code[259] = std::byte{0x00};
    code[260] = std::byte{0x00};

    // A tail JMP followed by data must not cause the data to be decoded and
    // overwritten as if it were more instructions.
    code[448] = std::byte{0xEB};
    code[449] = std::byte{0x7E};
    code[450] = std::byte{0xB8};
    code[451] = std::byte{0x2A};
    code[452] = std::byte{0x00};

    // An indirect tail JMP is terminal too.
    code[640] = std::byte{0xFF};
    code[641] = std::byte{0xE0};
    code[642] = std::byte{0xB8};
    code[643] = std::byte{0x2A};

    // INT3 and UD2 can be resumed by an exception handler, so they are
    // copied as ordinary instructions rather than treated as terminal padding.
    code[832] = std::byte{0xCC};
    code[833] = std::byte{0xB8};
    code[834] = std::byte{0x2A};
    code[835] = std::byte{0x00};
    code[836] = std::byte{0x00};
    code[837] = std::byte{0x00};
    code[838] = std::byte{0xC3};

    code[1024] = std::byte{0x0F};
    code[1025] = std::byte{0x0B}; // UD2
    code[1026] = std::byte{0xB8};
    code[1027] = std::byte{0x2A};
    code[1028] = std::byte{0x00};
    code[1029] = std::byte{0x00};
    code[1030] = std::byte{0x00};
    code[1031] = std::byte{0xC3};

    const auto snapshot = [code](std::size_t offset) {
        std::array<std::byte, 14> value{};
        std::memcpy(value.data(), code + offset, value.size());
        return value;
    };
    const auto ret_data_before = snapshot(256);
    const auto short_jmp_data_before = snapshot(448);
    const auto indirect_jmp_data_before = snapshot(640);
    const auto int3_before = snapshot(832);
    const auto ud2_before = snapshot(1024);

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    auto padded_ret = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    REQUIRE(padded_ret.has_value());
    REQUIRE(padded_ret->install(options).has_value());
    REQUIRE(padded_ret->original() != nullptr);
    REQUIRE(padded_ret->remove().has_value());
    REQUIRE(code[64] == std::byte{0xC3});
    REQUIRE(code[65] == std::byte{0x90});

    auto ret_with_data = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 256)}, &native_hook_detour, &backend);
    auto short_jmp_with_data = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 448)}, &native_hook_detour, &backend);
    auto indirect_jmp_with_data = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 640)}, &native_hook_detour, &backend);
    REQUIRE(ret_with_data.has_value());
    REQUIRE(short_jmp_with_data.has_value());
    REQUIRE(indirect_jmp_with_data.has_value());

    const auto ret_status = ret_with_data->install(options);
    const auto short_jmp_status = short_jmp_with_data->install(options);
    const auto indirect_jmp_status = indirect_jmp_with_data->install(options);
    REQUIRE_FALSE(ret_status.has_value());
    REQUIRE_FALSE(short_jmp_status.has_value());
    REQUIRE_FALSE(indirect_jmp_status.has_value());
    REQUIRE(ret_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(short_jmp_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(indirect_jmp_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 256, ret_data_before.data(), ret_data_before.size()) == 0);
    REQUIRE(std::memcmp(code + 448, short_jmp_data_before.data(), short_jmp_data_before.size()) == 0);
    REQUIRE(std::memcmp(code + 640, indirect_jmp_data_before.data(), indirect_jmp_data_before.size()) == 0);

    auto int3_prologue = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 832)}, &native_hook_detour, &backend);
    auto ud2_prologue = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 1024)}, &native_hook_detour, &backend);
    REQUIRE(int3_prologue.has_value());
    REQUIRE(ud2_prologue.has_value());
    REQUIRE(int3_prologue->install(options).has_value());
    REQUIRE(ud2_prologue->install(options).has_value());
    REQUIRE(int3_prologue->remove().has_value());
    REQUIRE(ud2_prologue->remove().has_value());
    REQUIRE(std::memcmp(code + 832, int3_before.data(), int3_before.size()) == 0);
    REQUIRE(std::memcmp(code + 1024, ud2_before.data(), ud2_before.size()) == 0);
}

TEST_CASE("Native inline backend preserves CET IBT landing pads and hooks after them",
          "[hook][native][compatibility][ibt]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t offset = 64;
    code[offset] = std::byte{0xF3};
    code[offset + 1] = std::byte{0x0F};
    code[offset + 2] = std::byte{0x1E};
#if defined(_M_X64) || defined(__x86_64__)
    code[offset + 3] = std::byte{0xFA}; // ENDBR64
#else
    code[offset + 3] = std::byte{0xFB}; // ENDBR32
#endif
    code[offset + 4] = std::byte{0xB8}; // mov eax,42
    const std::uint32_t return_value = 42;
    std::memcpy(code + offset + 5, &return_value, sizeof(return_value));
    code[offset + 9] = std::byte{0xC3};

    std::array<std::byte, 4> landing_pad_before{};
    std::memcpy(landing_pad_before.data(), code + offset, landing_pad_before.size());

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + offset)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    g_native_hook_original = hook->original();

    // The original landing pad remains the indirect-call entry point. Both it
    // and the trampoline start with the architecture-appropriate ENDBR.
    REQUIRE(std::memcmp(code + offset, landing_pad_before.data(), landing_pad_before.size()) == 0);
    REQUIRE(code[offset + 4] == std::byte{0xE9});
    const auto trampoline_address = reinterpret_cast<std::uintptr_t>(hook->original());
    REQUIRE(std::memcmp(reinterpret_cast<const void*>(trampoline_address),
                        landing_pad_before.data(),
                        landing_pad_before.size()) == 0);
    REQUIRE(reinterpret_cast<NativeHookFn>(base + offset)(7) == 142);
    REQUIRE(hook->original()(7) == 42);

    REQUIRE(hook->remove().has_value());
    g_native_hook_original = nullptr;
    REQUIRE(std::memcmp(code + offset, landing_pad_before.data(), landing_pad_before.size()) == 0);
    REQUIRE(reinterpret_cast<NativeHookFn>(base + offset)(7) == 42);
}

TEST_CASE("Native inline backend rejects detours located inside the stolen entry region",
          "[hook][native][validation]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    std::array<std::byte, 14> before{};
    std::memcpy(before.data(), code + 64, before.size());

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)},
        reinterpret_cast<NativeHookFn>(base + 65),
        &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::InvalidArgument);
    REQUIRE(std::memcmp(code + 64, before.data(), before.size()) == 0);
}

TEST_CASE("Native inline backend rejects non-executable detour addresses before patching",
          "[hook][native][validation]") {
    using namespace tessera;

    ExecutableRegionGuard target_region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(target_region.address != nullptr);

    ExecutableRegionGuard data_region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)};
    REQUIRE(data_region.address != nullptr);

    auto* target_code = static_cast<std::byte*>(target_region.address);
    std::memset(target_code, 0x90, 4096);
    target_code[64] = std::byte{0xB8};
    const std::uint32_t original_result = 42;
    std::memcpy(target_code + 65, &original_result, sizeof(original_result));
    target_code[69] = std::byte{0xC3};

    std::array<std::byte, 14> before{};
    std::memcpy(before.data(), target_code + 64, before.size());

    const auto target_address = reinterpret_cast<std::uintptr_t>(target_region.address) + 64;
    const auto invalid_detour = reinterpret_cast<NativeHookFn>(data_region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(target_address)},
        invalid_detour,
        &backend);
    REQUIRE_FALSE(hook.has_value());
    REQUIRE(hook.error().code == ErrorCode::AccessDenied);
    REQUIRE(std::memcmp(target_code + 64, before.data(), before.size()) == 0);
    REQUIRE(reinterpret_cast<NativeHookFn>(target_address)(7) == 42);

    // Hook::create validates the target too, before a Hook object can exist.
    // A valid detour cannot make a non-executable target eligible for patching.
    std::array<std::byte, 14> data_before{};
    std::memset(data_region.address, 0x90, 4096);
    std::memcpy(data_before.data(), data_region.address, data_before.size());
    auto non_executable_target = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(data_region.address))},
        &native_hook_detour,
        &backend);
    REQUIRE_FALSE(non_executable_target.has_value());
    REQUIRE(non_executable_target.error().code == ErrorCode::AccessDenied);
    REQUIRE(std::memcmp(data_region.address, data_before.data(), data_before.size()) == 0);
}

TEST_CASE("Native inline backend rejects common existing jump thunks without modifying them",
          "[hook][native][compatibility]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    code[64] = std::byte{0xE9};
    const std::int32_t near_jump_displacement = 0;
    std::memcpy(code + 65, &near_jump_displacement, sizeof(near_jump_displacement));

    code[256] = std::byte{0xFF};
    code[257] = std::byte{0x25};
    std::memset(code + 258, 0, 4);
    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    const std::uintptr_t thunk_destination = base + 512;
    std::memcpy(code + 262, &thunk_destination, sizeof(thunk_destination));

    std::array<std::byte, 14> e9_before{};
    std::array<std::byte, 14> ff25_before{};
    std::memcpy(e9_before.data(), code + 64, e9_before.size());
    std::memcpy(ff25_before.data(), code + 256, ff25_before.size());

    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    auto e9_hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    auto ff25_hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 256)}, &native_hook_detour, &backend);
    REQUIRE(e9_hook.has_value());
    REQUIRE(ff25_hook.has_value());

    const auto e9_status = e9_hook->install(options);
    const auto ff25_status = ff25_hook->install(options);
    REQUIRE_FALSE(e9_status.has_value());
    REQUIRE_FALSE(ff25_status.has_value());
    REQUIRE(e9_status.error().code == ErrorCode::Conflict);
    REQUIRE(ff25_status.error().code == ErrorCode::Conflict);
    REQUIRE(std::memcmp(code + 64, e9_before.data(), e9_before.size()) == 0);
    REQUIRE(std::memcmp(code + 256, ff25_before.data(), ff25_before.size()) == 0);
}

TEST_CASE("Native inline backend supports multiple simultaneous hooks and restores page protection",
          "[hook][native][lifecycle][protection]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    const auto write_constant = [code](std::size_t offset, std::uint32_t value) {
        code[offset] = std::byte{0xB8};
        std::memcpy(code + offset + 1, &value, sizeof(value));
        code[offset + 5] = std::byte{0xC3};
    };
    write_constant(64, 11);
    write_constant(256, 22);
    write_constant(448, 33);

    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &previous_protection));
    REQUIRE(previous_protection == PAGE_EXECUTE_READWRITE);

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto first = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour_1000, &backend);
    auto second = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 256)}, &native_hook_detour_2000, &backend);
    auto third = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 448)}, &native_hook_detour_3000, &backend);
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    REQUIRE(third.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(first->install(options).has_value());
    REQUIRE(second->install(options).has_value());
    REQUIRE(third->install(options).has_value());

    // Every architecture now uses a five-byte E9 entry patch; the RET at
    // byte +5 remains untouched even when x64 needs an out-of-range relay.
    REQUIRE(code[64] == std::byte{0xE9});
    REQUIRE(code[256] == std::byte{0xE9});
    REQUIRE(code[448] == std::byte{0xE9});
    REQUIRE(code[69] == std::byte{0xC3});
    REQUIRE(code[261] == std::byte{0xC3});
    REQUIRE(code[453] == std::byte{0xC3});

    REQUIRE(reinterpret_cast<NativeHookFn>(base + 64)(5) == 1005);
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 256)(5) == 2005);
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 448)(5) == 3005);
    REQUIRE(first->original()(5) == 11);
    const auto* first_trampoline = reinterpret_cast<const std::byte*>(
        reinterpret_cast<std::uintptr_t>(first->original()));
    REQUIRE(first_trampoline[0] == std::byte{0xF3});
    REQUIRE(first_trampoline[1] == std::byte{0x0F});
    REQUIRE(first_trampoline[2] == std::byte{0x1E});
#if defined(_M_X64) || defined(__x86_64__)
    REQUIRE(first_trampoline[3] == std::byte{0xFA});
#else
    REQUIRE(first_trampoline[3] == std::byte{0xFB});
#endif
    #if defined(_M_X64) || defined(__x86_64__)
    // The trampoline uses a complementary Jcc pair instead of an unconditional
    // tail JMP so Windows does not mistake the transfer for an epilog while
    // relocated stack-unwind state is still active.
    REQUIRE(first_trampoline[9] == std::byte{0x0F});
    REQUIRE(first_trampoline[10] == std::byte{0x84});
    REQUIRE(first_trampoline[15] == std::byte{0x0F});
    REQUIRE(first_trampoline[16] == std::byte{0x85});
    const auto* second_trampoline = reinterpret_cast<const std::byte*>(
        reinterpret_cast<std::uintptr_t>(second->original()));
    const auto* third_trampoline = reinterpret_cast<const std::byte*>(
        reinterpret_cast<std::uintptr_t>(third->original()));
    REQUIRE(second_trampoline[9] == std::byte{0x0F});
    REQUIRE(second_trampoline[10] == std::byte{0x84});
    REQUIRE(third_trampoline[9] == std::byte{0x0F});
    REQUIRE(third_trampoline[10] == std::byte{0x84});
#else
    REQUIRE(first_trampoline[9] == std::byte{0xE9});
    REQUIRE(reinterpret_cast<const std::byte*>(reinterpret_cast<std::uintptr_t>(second->original()))[9] == std::byte{0xE9});
    REQUIRE(reinterpret_cast<const std::byte*>(reinterpret_cast<std::uintptr_t>(third->original()))[9] == std::byte{0xE9});
#endif

#if defined(_M_X64) || defined(__x86_64__)
    const auto verify_entry_transfer = [](std::byte* entry, std::uintptr_t detour_address) {
        std::int32_t displacement = 0;
        std::memcpy(&displacement, entry + 1, sizeof(displacement));
        const auto entry_address = reinterpret_cast<std::uintptr_t>(entry);
        const auto transfer_target =
            static_cast<std::uintptr_t>(static_cast<std::intptr_t>(entry_address + 5) +
                                        static_cast<std::intptr_t>(displacement));
        const auto direct_delta = static_cast<std::intptr_t>(detour_address) -
                                  static_cast<std::intptr_t>(entry_address + 5);
        if (direct_delta >= (std::numeric_limits<std::int32_t>::min)() &&
            direct_delta <= (std::numeric_limits<std::int32_t>::max)()) {
            REQUIRE(transfer_target == detour_address);
        } else {
            const auto* relay = reinterpret_cast<const std::byte*>(transfer_target);
            REQUIRE(relay[0] == std::byte{0xFF});
            REQUIRE(relay[1] == std::byte{0x25});
            std::uint32_t zero_displacement = 1;
            std::memcpy(&zero_displacement, relay + 2, sizeof(zero_displacement));
            REQUIRE(zero_displacement == 0);
            std::uint64_t absolute_target = 0;
            std::memcpy(&absolute_target, relay + 6, sizeof(absolute_target));
            REQUIRE(absolute_target == static_cast<std::uint64_t>(detour_address));
        }
    };
    verify_entry_transfer(code + 64, reinterpret_cast<std::uintptr_t>(&native_hook_detour_1000));
    verify_entry_transfer(code + 256, reinterpret_cast<std::uintptr_t>(&native_hook_detour_2000));
    verify_entry_transfer(code + 448, reinterpret_cast<std::uintptr_t>(&native_hook_detour_3000));
#endif
    REQUIRE(second->original()(5) == 22);
    REQUIRE(third->original()(5) == 33);

    REQUIRE(third->remove().has_value());
    REQUIRE(second->remove().has_value());
    REQUIRE(first->remove().has_value());
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 64)(5) == 11);
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 256)(5) == 22);
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 448)(5) == 33);

    MEMORY_BASIC_INFORMATION information{};
    REQUIRE(::VirtualQuery(region.address, &information, sizeof(information)) == sizeof(information));
    REQUIRE(information.Protect == PAGE_EXECUTE_READ);
}

#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native inline x64 backend routes a far detour through its near relay",
          "[hook][native][relay][integration]") {
    using namespace tessera;

    void* allocation = ::VirtualAlloc(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x10000000)),
        4096,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (allocation == nullptr) {
        allocation = ::VirtualAlloc(
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x20000000)),
            4096,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
    }
    if (allocation == nullptr) {
        allocation = ::VirtualAlloc(
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x30000000)),
            4096,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
    }
    ExecutableRegionGuard region{allocation};
    REQUIRE(region.address != nullptr);

    // Place an IBT-valid detour far from the low target allocation. The relay's
    // indirect absolute jump must land on this ENDBR64 entry.
    void* detour_allocation = nullptr;
    constexpr std::array<std::uintptr_t, 3> detour_candidates{
        0x700000000000ULL, 0x600000000000ULL, 0x500000000000ULL};
    for (const auto candidate : detour_candidates) {
        detour_allocation = ::VirtualAlloc(reinterpret_cast<void*>(candidate),
                                           4096,
                                           MEM_RESERVE | MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
        if (detour_allocation != nullptr) {
            break;
        }
    }
    ExecutableRegionGuard detour_region{detour_allocation};
    REQUIRE(detour_region.address != nullptr);
    auto* detour_code = static_cast<std::byte*>(detour_region.address);
    constexpr std::array<std::byte, 8> far_detour_bytes{
        std::byte{0xF3}, std::byte{0x0F}, std::byte{0x1E}, std::byte{0xFA},
        std::byte{0x8D}, std::byte{0x41}, std::byte{0x64}, std::byte{0xC3}};
    std::memcpy(detour_code, far_detour_bytes.data(), far_detour_bytes.size());
    const auto far_detour = reinterpret_cast<NativeHookFn>(detour_region.address);

    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    code[64] = std::byte{0xF3};
    code[65] = std::byte{0x0F};
    code[66] = std::byte{0x1E};
    code[67] = std::byte{0xFA}; // ENDBR64
    code[68] = std::byte{0xB8};
    const std::uint32_t return_value = 42;
    std::memcpy(code + 69, &return_value, sizeof(return_value));
    code[73] = std::byte{0xC3};

    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &previous_protection));

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    const auto detour_address = reinterpret_cast<std::uintptr_t>(far_detour);
    const auto direct_delta = static_cast<std::intptr_t>(detour_address) -
                              static_cast<std::intptr_t>(base + 73);
    REQUIRE(direct_delta < (std::numeric_limits<std::int32_t>::min)() ||
            direct_delta > (std::numeric_limits<std::int32_t>::max)());

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, far_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    REQUIRE(code[64] == std::byte{0xF3});
    REQUIRE(code[68] == std::byte{0xE9});
    std::int32_t entry_displacement = 0;
    std::memcpy(&entry_displacement, code + 69, sizeof(entry_displacement));
    const auto relay_address = static_cast<std::uintptr_t>(
        static_cast<std::intptr_t>(base + 73) + entry_displacement);
    REQUIRE(relay_address != detour_address);
    const auto* relay = reinterpret_cast<const std::byte*>(relay_address);
    REQUIRE(relay[0] == std::byte{0xFF});
    REQUIRE(relay[1] == std::byte{0x25});
    std::uint32_t zero_displacement = 1;
    std::memcpy(&zero_displacement, relay + 2, sizeof(zero_displacement));
    REQUIRE(zero_displacement == 0);
    std::uint64_t relay_target = 0;
    std::memcpy(&relay_target, relay + 6, sizeof(relay_target));
    REQUIRE(relay_target == static_cast<std::uint64_t>(detour_address));

    REQUIRE(reinterpret_cast<NativeHookFn>(base + 64)(5) == 105);
    REQUIRE(hook->original()(5) == 42);
    REQUIRE(hook->remove().has_value());
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 64)(5) == 42);
    REQUIRE(code[64] == std::byte{0xF3});
    REQUIRE(code[68] == std::byte{0xB8});
}
#endif

