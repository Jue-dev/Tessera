#include "patch_hook_test_support.hpp"
#include "hook/backends/native_unwind.hpp"


#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native x64 unwind registration remains alive until an explicit callable lease drains",
          "[hook][native][unwind][lifecycle][integration]") {
    using namespace tessera;

    g_callable_lease_entered.store(false, std::memory_order_release);
    g_callable_lease_release.store(false, std::memory_order_release);

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    code[target_offset + 0u] = std::byte{0x48};
    code[target_offset + 1u] = std::byte{0x83};
    code[target_offset + 2u] = std::byte{0xEC};
    code[target_offset + 3u] = std::byte{0x28}; // sub rsp, 0x28
    code[target_offset + 4u] = std::byte{0x48};
    code[target_offset + 5u] = std::byte{0xB8}; // mov rax, imm64
    const auto helper_address =
        reinterpret_cast<std::uintptr_t>(&blocking_trampoline_function);
    std::memcpy(code + target_offset + 6u, &helper_address, sizeof(helper_address));
    code[target_offset + 14u] = std::byte{0xFF};
    code[target_offset + 15u] = std::byte{0xD0}; // call rax
    code[target_offset + 16u] = std::byte{0x48};
    code[target_offset + 17u] = std::byte{0x83};
    code[target_offset + 18u] = std::byte{0xC4};
    code[target_offset + 19u] = std::byte{0x28}; // add rsp, 0x28
    code[target_offset + 20u] = std::byte{0xC3}; // ret

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    // The test record carries no handler or chained-unwind flags.
    source_info->size_of_prolog = 4u;
    source_info->count_of_codes = 1u;
    source_info->frame_register_and_offset = 0u;
    
    set_test_unwind_code(
        source_info, 0u,
        {4u, static_cast<UCHAR>(kTestUnwindOpAllocSmall | (4u << 4u))});
    // Operation info 4 means (0x28 - 8) / 8.

    struct SourceFunctionTableGuard {
        RUNTIME_FUNCTION entry{};
        bool registered = false;
        ~SourceFunctionTableGuard() noexcept {
            if (registered && !::RtlDeleteFunctionTable(&entry)) {
                std::terminate();
            }
        }
    } source_table;
    source_table.entry.BeginAddress = static_cast<DWORD>(target_offset);
    source_table.entry.EndAddress = static_cast<DWORD>(target_offset + 32u);
    source_table.entry.UnwindData = static_cast<DWORD>(source_unwind_offset);
    REQUIRE(::RtlAddFunctionTable(
        &source_table.entry,
        1u,
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(region.address))));
    source_table.registered = true;

    DWORD old_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &old_protection));

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(code + target_offset))},
        &blocking_lease_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    g_lease_detour_original.store(trampoline, std::memory_order_release);
    REQUIRE(trampoline != nullptr);
    DWORD64 table_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
                &table_image_base,
                nullptr) != nullptr);

    std::atomic<int> call_result{-1};
    std::atomic<bool> remove_started{false};
    std::atomic<bool> remove_finished{false};
    std::atomic<bool> remove_succeeded{false};
    std::thread caller([&] {
        auto lease = hook->acquire();
        const NativeHookFn target_entry = lease.target();
        const NativeHookFn callable = lease.get();
        call_result.store(
            target_entry != nullptr && callable == trampoline ? target_entry(5) : -1,
            std::memory_order_release);
    });

    const auto entered_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!g_callable_lease_entered.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < entered_deadline) {
        std::this_thread::yield();
    }
    const bool call_entered =
        g_callable_lease_entered.load(std::memory_order_acquire);
    if (!call_entered) {
        g_callable_lease_release.store(true, std::memory_order_release);
        caller.join();
    }
    REQUIRE(call_entered);

    std::thread remover([&] {
        remove_started.store(true, std::memory_order_release);
        const auto result = hook->remove();
        remove_succeeded.store(result.has_value(), std::memory_order_release);
        remove_finished.store(true, std::memory_order_release);
    });

    const auto remove_start_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!remove_started.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < remove_start_deadline) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const bool remove_finished_while_leased =
        remove_finished.load(std::memory_order_acquire);
    DWORD64 live_table_base = 0;
    const bool table_alive_while_leased =
        ::RtlLookupFunctionEntry(
            static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
            &live_table_base,
            nullptr) != nullptr;

    g_callable_lease_release.store(true, std::memory_order_release);
    caller.join();
    remover.join();

    REQUIRE_FALSE(remove_finished_while_leased);
    REQUIRE(table_alive_while_leased);
    REQUIRE(remove_succeeded.load(std::memory_order_acquire));
    REQUIRE(remove_finished.load(std::memory_order_acquire));
    REQUIRE(call_result.load(std::memory_order_acquire) == 47);
    DWORD64 removed_table_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
                &removed_table_base,
                nullptr) == nullptr);
    g_lease_detour_original.store(nullptr, std::memory_order_release);
}
#endif

#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native x64 unwind unregister failure restores the patch and keeps the token retryable",
          "[hook][native][unwind][failure][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    constexpr std::size_t target_offset = 64u;
    code[target_offset] = std::byte{0xB8};
    constexpr std::uint32_t return_value = 42u;
    std::memcpy(code + target_offset + 1u, &return_value, sizeof(return_value));
    code[target_offset + 5u] = std::byte{0xC3};
    std::array<std::byte, 8> original{};
    std::memcpy(original.data(), code + target_offset, original.size());

    DWORD old_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &old_protection));

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(code + target_offset))},
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(function_entry != nullptr);

    struct FunctionTableRecovery {
        PRUNTIME_FUNCTION entry = nullptr;
        DWORD64 image_base = 0;
        bool needs_restore = false;
        ~FunctionTableRecovery() noexcept {
            if (needs_restore &&
                !::RtlAddFunctionTable(entry, 1u, image_base)) {
                std::terminate();
            }
        }
    } recovery{function_entry, image_base, false};

    REQUIRE(::RtlDeleteFunctionTable(function_entry));
    recovery.needs_restore = true;

    const auto first_remove = hook->remove();
    if (first_remove) {
        // Keep the guard from registering a table whose owning hook state has
        // already been destroyed if the expected unregister failure regresses.
        recovery.needs_restore = false;
    }
    REQUIRE_FALSE(first_remove.has_value());
    REQUIRE(first_remove.error().code == ErrorCode::IoError);
    REQUIRE(hook->installed());
    REQUIRE(code[target_offset] == std::byte{0xE9});
    DWORD64 missing_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
                &missing_image_base,
                nullptr) == nullptr);

    REQUIRE(::RtlAddFunctionTable(function_entry, 1u, image_base));
    recovery.needs_restore = false;

    REQUIRE(hook->remove().has_value());
    REQUIRE_FALSE(hook->installed());
    REQUIRE(std::memcmp(code + target_offset, original.data(), original.size()) == 0);
    DWORD64 removed_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
                &removed_image_base,
                nullptr) == nullptr);
}

#endif

#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native x64 unwind registration failure does not publish ownership",
          "[hook][native][unwind][failure]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)};
    REQUIRE(region.address != nullptr);

    // Inject only the private registration operation. Production calls retain
    // the default real RtlAddFunctionTable function pointer and no global state
    // or public SDK ABI is introduced.
    const auto reject_registration = +[](PRUNTIME_FUNCTION, DWORD, DWORD64) noexcept -> BOOLEAN {
        return FALSE;
    };
    RUNTIME_FUNCTION entry{};
    entry.BeginAddress = 0u;
    entry.EndAddress = 16u;
    entry.UnwindData = 32u;
    bool registered = false;

    const auto status = detail::native_hook::register_trampoline_unwind(
        entry, registered, region.address, reject_registration);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::IoError);
    REQUIRE(status.error().operation == "RtlAddFunctionTable");
    REQUIRE_FALSE(registered);
}
#endif
