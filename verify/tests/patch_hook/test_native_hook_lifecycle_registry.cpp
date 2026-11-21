#include "patch_hook_test_support.hpp"
#include "hook/backends/native_trampoline.hpp"

namespace {
int g_native_trampoline_allocation_calls = 0;

LPVOID WINAPI fail_native_trampoline_allocation(
    LPVOID, SIZE_T, DWORD, DWORD) noexcept {
    ++g_native_trampoline_allocation_calls;
    return nullptr;
}

void WINAPI one_step_native_trampoline_system_info(LPSYSTEM_INFO info) noexcept {
    info->dwAllocationGranularity = 0x70000000u;
}
} // namespace


TEST_CASE("Native inline backend relocates x64 RIP-relative code and restores the target", "[hook][native]") {
    using namespace tessera;

#if defined(TESSERA_TEST_WITH_DETOURS)
    HookBackend* native_backend = &native_inline_hook_backend();
#else
    HookBackend* native_backend = nullptr; // Exercise the no-Detours default selection.
#endif
    auto hook = Hook<NativeHookFn>::create(
        &native_hook_target, &native_hook_detour, native_backend);
    REQUIRE(hook.has_value());
    REQUIRE_FALSE(hook->installed());

    NativeHookFn volatile entry = &native_hook_target;
    const int original_result = entry(29);
    REQUIRE(original_result == 29 + 3 + 5 + 7 + 11 + 13 + 17 + 19 + 23);

    HookOptions options{};
    // This test intentionally exercises a single-threaded transaction.
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    REQUIRE(hook->installed());
    REQUIRE(hook->install(options).has_value()); // repeated install is idempotent

    g_native_hook_original = hook->original();
    REQUIRE(g_native_hook_original != nullptr);
    REQUIRE(g_native_hook_original(29) == original_result);
    REQUIRE(entry(29) == original_result + 100);

    // A second native hook cannot silently stack over the first hook's entry jump.
    auto duplicate = Hook<NativeHookFn>::create(
        &native_hook_target, &native_hook_detour, native_backend);
    REQUIRE(duplicate.has_value());
    auto duplicate_status = duplicate->install(options);
    REQUIRE_FALSE(duplicate_status.has_value());
    REQUIRE(duplicate_status.error().code == ErrorCode::Conflict);
    REQUIRE(entry(29) == original_result + 100);

    REQUIRE(hook->remove().has_value());
    REQUIRE_FALSE(hook->installed());
    REQUIRE(hook->remove().has_value()); // repeated remove is idempotent
    g_native_hook_original = nullptr;
    REQUIRE(entry(29) == original_result);
}

TEST_CASE("Native inline backend rejects overlapping patches and releases ownership on detach",
           "[hook][native][registry]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr,
                       4096,
                       MEM_RESERVE | MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    std::memset(region.address, 0x90, 4096);

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    const Address first_target{static_cast<std::uint64_t>(base + 32)};
    // Starts inside the first hook's minimum/actual overwritten prologue on
    // both x86 (5 bytes) and x64 (14 bytes).
    const Address overlapping_target{static_cast<std::uint64_t>(base + 34)};

    HookBackend& backend = native_inline_hook_backend();
    auto first = Hook<NativeHookFn>::create(first_target, &native_hook_detour, &backend);
    auto overlapping =
        Hook<NativeHookFn>::create(overlapping_target, &native_hook_detour, &backend);
    REQUIRE(first.has_value());
    REQUIRE(overlapping.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(first->install(options).has_value());

    const auto overlap_status = overlapping->install(options);
    REQUIRE_FALSE(overlap_status.has_value());
    REQUIRE(overlap_status.error().code == ErrorCode::Conflict);

    // Removing the first owner must release the range so the second hook can
    // safely claim it after the original bytes have been restored.
    REQUIRE(first->remove().has_value());
    REQUIRE_FALSE(first->installed());
    REQUIRE(overlapping->install(options).has_value());
    REQUIRE(overlapping->installed());
    REQUIRE(overlapping->remove().has_value());
    REQUIRE_FALSE(overlapping->installed());
}

TEST_CASE("Native inline detach preserves ownership after external patch conflict",
           "[hook][native][lifecycle]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr,
                       4096,
                       MEM_RESERVE | MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);

    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    const auto base = reinterpret_cast<std::uintptr_t>(region.address);

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 128)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    REQUIRE(hook->installed());

    // Simulate another patch owner changing a byte in our installed entry jump.
    const std::byte installed_byte = code[129];
    code[129] = installed_byte == std::byte{0xCC}
                    ? std::byte{0xCD}
                    : std::byte{0xCC};

    const auto conflict = hook->remove();
    REQUIRE_FALSE(conflict.has_value());
    REQUIRE(conflict.error().code == ErrorCode::Conflict);
    REQUIRE(hook->installed());

    // Restore the exact bytes owned by this hook and retry detach.
    code[129] = installed_byte;
    REQUIRE(hook->remove().has_value());
    REQUIRE_FALSE(hook->installed());
    REQUIRE(code[128] == std::byte{0x90});
}
