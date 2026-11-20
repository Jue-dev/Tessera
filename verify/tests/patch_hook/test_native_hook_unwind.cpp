#include "patch_hook_test_support.hpp"


#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native x64 trampoline maps ALLOC_LARGE and SET_FPREG together",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    const std::array<std::byte, 15> prologue{
        std::byte{0xF3}, std::byte{0x0F}, std::byte{0x1E}, std::byte{0xFA}, // endbr64
        std::byte{0x55},                                           // push rbp
        std::byte{0x48}, std::byte{0x8B}, std::byte{0xEC},         // mov rbp, rsp
        std::byte{0x48}, std::byte{0x81}, std::byte{0xEC},         // sub rsp, 0x100
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}};
    std::memcpy(code + target_offset, prologue.data(), prologue.size());

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = static_cast<UCHAR>(prologue.size());
    source_info->count_of_codes = 4u;
    source_info->frame_register_and_offset = 0x05u; // RBP, zero frame offset
    set_test_unwind_code(source_info, 0u,
                         {15u, static_cast<UCHAR>(1u)}); // UWOP_ALLOC_LARGE, OpInfo=0
    const USHORT allocation_in_eight_byte_units = 0x20u;
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset +
                    1u * sizeof(TestUnwindCode),
                &allocation_in_eight_byte_units,
                sizeof(allocation_in_eight_byte_units));
    set_test_unwind_code(source_info, 2u,
                         {8u, static_cast<UCHAR>(3u)}); // UWOP_SET_FPREG
    set_test_unwind_code(
        source_info, 3u,
        {5u, static_cast<UCHAR>(kTestUnwindOpPushNonVol | (5u << 4u))}); // push rbp

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
    source_table.entry.EndAddress = static_cast<DWORD>(target_offset + 64u);
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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);

    alignas(16) std::array<std::byte, 512> fake_stack{};
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + 344u;
    const auto saved_frame_pointer = static_cast<DWORD64>(0x1122334455667788ull);
    const DWORD64 return_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer - sizeof(DWORD64)),
                &saved_frame_pointer,
                sizeof(saved_frame_pointer));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer),
                &return_address,
                sizeof(return_address));

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = static_cast<DWORD64>(
        reinterpret_cast<std::uintptr_t>(trampoline) +
        kTestTrampolineEntryPrefixSize + (prologue.size() - kTestTrampolineEntryPrefixSize));
    context.Rsp = static_cast<DWORD64>(entry_stack_pointer - sizeof(DWORD64) - 0x100u);
    context.Rbp = static_cast<DWORD64>(entry_stack_pointer - sizeof(DWORD64));
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    (void)::RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        image_base,
        context.Rip,
        trampoline_function,
        &context,
        &handler_data,
        &establisher_frame,
        nullptr);

    REQUIRE(context.Rip == return_address);
    REQUIRE(context.Rsp == entry_stack_pointer + sizeof(DWORD64));
    REQUIRE(context.Rbp == saved_frame_pointer);
    REQUIRE(hook->remove().has_value());
}

TEST_CASE("Native x64 trampoline restores a saved nonvolatile XMM register",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    const std::array<std::byte, 14> function_code{
        std::byte{0x48}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x28}, // sub rsp, 0x28
        std::byte{0x0F}, std::byte{0x29}, std::byte{0x74},
        std::byte{0x24}, std::byte{0x10},                                // movaps [rsp+10], xmm6
        std::byte{0x0F}, std::byte{0x28}, std::byte{0x74},
        std::byte{0x24}, std::byte{0x10}};                               // movaps xmm6, [rsp+10]
    std::memcpy(code + target_offset, function_code.data(), function_code.size());
    code[target_offset + function_code.size() + 0u] = std::byte{0x48};
    code[target_offset + function_code.size() + 1u] = std::byte{0x83};
    code[target_offset + function_code.size() + 2u] = std::byte{0xC4};
    code[target_offset + function_code.size() + 3u] = std::byte{0x28};
    code[target_offset + function_code.size() + 4u] = std::byte{0xC3};

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = 9u;
    source_info->count_of_codes = 3u;
    source_info->frame_register_and_offset = 0u;
    set_test_unwind_code(
        source_info, 0u,
        {9u, static_cast<UCHAR>(8u | (6u << 4u))}); // UWOP_SAVE_XMM128 XMM6
    const USHORT xmm_save_offset_in_sixteen_byte_units = 1u;
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset + sizeof(TestUnwindCode),
                &xmm_save_offset_in_sixteen_byte_units,
                sizeof(xmm_save_offset_in_sixteen_byte_units));
    set_test_unwind_code(
        source_info, 2u,
        {4u, static_cast<UCHAR>(kTestUnwindOpAllocSmall | (4u << 4u))});

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
    source_table.entry.EndAddress =
        static_cast<DWORD>(target_offset + function_code.size() + 16u);
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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);

    alignas(16) std::array<std::byte, 256> fake_stack{};
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + 88u;
    const auto current_stack_pointer = entry_stack_pointer - 0x28u;
    const DWORD64 return_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer),
                &return_address,
                sizeof(return_address));
    std::array<std::byte, 16> expected_xmm6{};
    for (std::size_t index = 0; index < expected_xmm6.size(); ++index) {
        expected_xmm6[index] = static_cast<std::byte>(index + 0x40u);
    }
    std::memcpy(reinterpret_cast<void*>(current_stack_pointer + 0x10u),
                expected_xmm6.data(),
                expected_xmm6.size());

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = static_cast<DWORD64>(
        reinterpret_cast<std::uintptr_t>(trampoline) +
        kTestTrampolineEntryPrefixSize + 9u);
    context.Rsp = static_cast<DWORD64>(current_stack_pointer);
    std::memset(&context.Xmm6, 0, sizeof(context.Xmm6));
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    (void)::RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        image_base,
        context.Rip,
        trampoline_function,
        &context,
        &handler_data,
        &establisher_frame,
        nullptr);

    REQUIRE(context.Rip == return_address);
    REQUIRE(context.Rsp == entry_stack_pointer + sizeof(DWORD64));
    REQUIRE(std::memcmp(&context.Xmm6, expected_xmm6.data(),
                        expected_xmm6.size()) == 0);
    REQUIRE(hook->remove().has_value());
}

#endif // x64 multi-opcode unwind tests

#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native x64 trampoline remaps unwind offsets and unwinds an exception in relocated prologue",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // The first four bytes allocate the x64 shadow space. INT3 is deliberately
    // the fifth stolen byte, so the exception is raised inside the trampoline
    // after the relocated stack adjustment has executed.
    constexpr std::size_t target_offset = 64u;
    code[target_offset + 0u] = std::byte{0x48};
    code[target_offset + 1u] = std::byte{0x83};
    code[target_offset + 2u] = std::byte{0xEC};
    code[target_offset + 3u] = std::byte{0x28};
    code[target_offset + 4u] = std::byte{0xCC};
    code[target_offset + 5u] = std::byte{0x48};
    code[target_offset + 6u] = std::byte{0x83};
    code[target_offset + 7u] = std::byte{0xC4};
    code[target_offset + 8u] = std::byte{0x28};
    code[target_offset + 9u] = std::byte{0xC3};

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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 trampoline_image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &trampoline_image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);
    const auto* trampoline_info = reinterpret_cast<const TestUnwindInfo*>(
        trampoline_image_base + trampoline_function->UnwindData);
    REQUIRE((trampoline_info->version_and_flags & 0x07u) == 1u);
    REQUIRE(trampoline_info->count_of_codes == 1u);
    REQUIRE(trampoline_info->size_of_prolog == 8u);
    const TestUnwindCode trampoline_unwind_code =
        get_test_unwind_code(trampoline_info, 0u);
    REQUIRE(trampoline_unwind_code.code_offset == 8u);
    REQUIRE((trampoline_unwind_code.operation & 0x0Fu) == kTestUnwindOpAllocSmall);
    REQUIRE((trampoline_unwind_code.operation >> 4u) == 4u);

    // The OS exception dispatcher must find the generated RUNTIME_FUNCTION,
    // apply the translated ALLOC_SMALL unwind code, and reach this handler.
    REQUIRE(invoke_breakpoint_trampoline(trampoline) == EXCEPTION_BREAKPOINT);

    void* const trampoline_address =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(trampoline));
    REQUIRE(hook->remove().has_value());
    DWORD64 removed_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline_address)),
                &removed_image_base,
                nullptr) == nullptr);
}
#endif

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

TEST_CASE("Native x64 trampoline unwinds multiple pushed nonvolatile registers",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    code[target_offset + 0u] = std::byte{0x53}; // push rbx
    code[target_offset + 1u] = std::byte{0x56}; // push rsi
    code[target_offset + 2u] = std::byte{0xCC}; // exception while both pushes are active
    code[target_offset + 3u] = std::byte{0x90};
    code[target_offset + 4u] = std::byte{0x90};
    code[target_offset + 5u] = std::byte{0x5E}; // pop rsi
    code[target_offset + 6u] = std::byte{0x5B}; // pop rbx
    code[target_offset + 7u] = std::byte{0xB8};
    constexpr std::uint32_t return_value = 42u;
    std::memcpy(code + target_offset + 8u, &return_value, sizeof(return_value));
    code[target_offset + 12u] = std::byte{0xC3};

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = 2u;
    source_info->count_of_codes = 2u;
    source_info->frame_register_and_offset = 0u;
    const std::array<TestUnwindCode, 2> unwind_codes{{
        {2u, static_cast<UCHAR>(kTestUnwindOpPushNonVol | (6u << 4u))}, // push rsi
        {1u, static_cast<UCHAR>(kTestUnwindOpPushNonVol | (3u << 4u))}, // push rbx
    }};
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset,
                unwind_codes.data(),
                sizeof(unwind_codes));

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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
                &image_base,
                nullptr) != nullptr);
    REQUIRE(invoke_breakpoint_trampoline(trampoline) == EXCEPTION_BREAKPOINT);

    REQUIRE(hook->remove().has_value());
    DWORD64 removed_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
                &removed_image_base,
                nullptr) == nullptr);
}

TEST_CASE("Native x64 trampoline maps multi-slot UWOP_ALLOC_LARGE for virtual unwind",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    constexpr std::uint32_t allocation_size = 0x80000u;
    code[target_offset + 0u] = std::byte{0x48};
    code[target_offset + 1u] = std::byte{0x81};
    code[target_offset + 2u] = std::byte{0xEC};
    std::memcpy(code + target_offset + 3u, &allocation_size, sizeof(allocation_size));
    code[target_offset + 7u] = std::byte{0x48};
    code[target_offset + 8u] = std::byte{0x81};
    code[target_offset + 9u] = std::byte{0xC4};
    std::memcpy(code + target_offset + 10u, &allocation_size, sizeof(allocation_size));
    code[target_offset + 14u] = std::byte{0xB8};
    constexpr std::uint32_t return_value = 42u;
    std::memcpy(code + target_offset + 15u, &return_value, sizeof(return_value));
    code[target_offset + 19u] = std::byte{0xC3};

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = 7u;
    source_info->count_of_codes = 3u; // operation plus two payload slots
    source_info->frame_register_and_offset = 0u;
    const TestUnwindCode allocation_operation{
        7u, static_cast<UCHAR>(1u | (1u << 4u))}; // UWOP_ALLOC_LARGE, OpInfo=1
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset,
                &allocation_operation,
                sizeof(allocation_operation));
    const std::uint32_t encoded_allocation = allocation_size;
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset + sizeof(TestUnwindCode),
                &encoded_allocation,
                sizeof(encoded_allocation));

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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);

    // Simulate execution after SUB RSP, 0x80000, at the trampoline's return
    // jump. RtlVirtualUnwind must apply the translated three-slot allocation.
    std::vector<std::byte> fake_stack(
        static_cast<std::size_t>(allocation_size) + 64u);
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + allocation_size + 16u;
    const DWORD64 return_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer),
                &return_address,
                sizeof(return_address));

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = static_cast<DWORD64>(
        reinterpret_cast<std::uintptr_t>(trampoline) + kTestTrampolineEntryPrefixSize + 7u);
    context.Rsp = static_cast<DWORD64>(entry_stack_pointer - allocation_size);
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    (void)::RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        image_base,
        context.Rip,
        trampoline_function,
        &context,
        &handler_data,
        &establisher_frame,
        nullptr);

    REQUIRE(context.Rip == return_address);
    REQUIRE(context.Rsp == entry_stack_pointer + sizeof(DWORD64));

    REQUIRE(hook->remove().has_value());
}

TEST_CASE("Native x64 trampoline maps multi-slot UWOP_SAVE_NONVOL for virtual unwind",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    // MOV [RSP+0x20], RSI; the save completes at source CodeOffset 5.
    const std::array<std::byte, 5> save_instruction{
        std::byte{0x48}, std::byte{0x89}, std::byte{0x74},
        std::byte{0x24}, std::byte{0x20}};
    std::memcpy(code + target_offset, save_instruction.data(), save_instruction.size());
    // Restore the nonvolatile register in the source function's epilogue.
    code[target_offset + 5u] = std::byte{0x48};
    code[target_offset + 6u] = std::byte{0x8B};
    code[target_offset + 7u] = std::byte{0x74};
    code[target_offset + 8u] = std::byte{0x24};
    code[target_offset + 9u] = std::byte{0x20};
    code[target_offset + 10u] = std::byte{0xC3};

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = 5u;
    source_info->count_of_codes = 2u;
    source_info->frame_register_and_offset = 0u;
    const TestUnwindCode save_operation{
        5u, static_cast<UCHAR>(4u | (6u << 4u))}; // UWOP_SAVE_NONVOL RSI
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset,
                &save_operation,
                sizeof(save_operation));
    const USHORT scaled_stack_offset = 4u; // 0x20 / sizeof(ULONG64)
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset + sizeof(TestUnwindCode),
                &scaled_stack_offset,
                sizeof(scaled_stack_offset));

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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);

    alignas(16) std::array<std::byte, 128> fake_stack{};
    // RSP is 8 mod 16 at a Windows x64 function entry (return address on top).
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + 24u;
    const DWORD64 return_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    constexpr DWORD64 saved_rsi = 0x0123456789ABCDEFull;
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer),
                &return_address,
                sizeof(return_address));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer + 0x20u),
                &saved_rsi,
                sizeof(saved_rsi));

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = static_cast<DWORD64>(
        reinterpret_cast<std::uintptr_t>(trampoline) +
        kTestTrampolineEntryPrefixSize + save_instruction.size());
    context.Rsp = static_cast<DWORD64>(entry_stack_pointer);
    context.Rsi = 0u;
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    (void)::RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        image_base,
        context.Rip,
        trampoline_function,
        &context,
        &handler_data,
        &establisher_frame,
        nullptr);

    REQUIRE(context.Rip == return_address);
    REQUIRE(context.Rsp == entry_stack_pointer + sizeof(DWORD64));
    REQUIRE(context.Rsi == saved_rsi);

    REQUIRE(hook->remove().has_value());
}

TEST_CASE("Native x64 trampoline maps far UWOP_SAVE_NONVOL and UWOP_ALLOC_LARGE",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    constexpr std::uint32_t stack_allocation = 0x28u;
    constexpr std::uint32_t save_offset = 0x80000u;
    const std::array<std::byte, 12> prologue{
        std::byte{0x48}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x28},
        std::byte{0x48}, std::byte{0x89}, std::byte{0xB4}, std::byte{0x24},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x08}, std::byte{0x00}}; // sub rsp, 0x28; mov [rsp+0x80000], rsi
    std::memcpy(code + target_offset, prologue.data(), prologue.size());
    const std::array<std::byte, 16> epilogue{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0xB4},
        std::byte{0x24}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x08}, std::byte{0x00}, // mov rsi, [rsp+0x80000]
        std::byte{0x48}, std::byte{0x81}, std::byte{0xC4},
        std::byte{0x28}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0xC3}};
    std::memcpy(code + target_offset + prologue.size(),
                epilogue.data(), epilogue.size());

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 32u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = static_cast<UCHAR>(prologue.size());
    source_info->count_of_codes = 4u;
    set_test_unwind_code(
        source_info, 0u,
        {12u, static_cast<UCHAR>(5u | (6u << 4u))}); // UWOP_SAVE_NONVOL_FAR RSI
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset + sizeof(TestUnwindCode),
                &save_offset, sizeof(save_offset));
    set_test_unwind_code(
        source_info, 3u, {4u, static_cast<UCHAR>(2u | (4u << 4u))}); // UWOP_ALLOC_SMALL, 0x28 bytes
    

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
    source_table.entry.EndAddress = static_cast<DWORD>(target_offset + 64u);
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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);

    std::vector<std::byte> fake_stack(3u * 1024u * 1024u);
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + 0x100008u;
    const auto current_stack_pointer = entry_stack_pointer - stack_allocation;
    constexpr DWORD64 saved_rsi = 0xFEDCBA9876543210ull;
    const DWORD64 return_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer),
                &return_address, sizeof(return_address));
    std::memcpy(reinterpret_cast<void*>(current_stack_pointer + save_offset),
                &saved_rsi, sizeof(saved_rsi));

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = static_cast<DWORD64>(
        reinterpret_cast<std::uintptr_t>(trampoline) +
        kTestTrampolineEntryPrefixSize + prologue.size());
    context.Rsp = static_cast<DWORD64>(current_stack_pointer);
    context.Rsi = 0u;
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    (void)::RtlVirtualUnwind(
        UNW_FLAG_NHANDLER, image_base, context.Rip, trampoline_function,
        &context, &handler_data, &establisher_frame, nullptr);

    REQUIRE(context.Rip == return_address);
    REQUIRE(context.Rsp == entry_stack_pointer + sizeof(DWORD64));
    REQUIRE(context.Rsi == saved_rsi);
    REQUIRE(hook->remove().has_value());
}

TEST_CASE("Native x64 trampoline maps far UWOP_SAVE_XMM128 and UWOP_ALLOC_LARGE",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    constexpr std::uint32_t stack_allocation = 0x28u;
    constexpr std::uint32_t save_offset = 0x100000u;
    const std::array<std::byte, 12> prologue{
        std::byte{0x48}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x28},
        std::byte{0x0F}, std::byte{0x29}, std::byte{0xB4}, std::byte{0x24},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x10}, std::byte{0x00}}; // sub rsp, 0x28; movaps [rsp+0x100000], xmm6
    std::memcpy(code + target_offset, prologue.data(), prologue.size());
    const std::array<std::byte, 16> epilogue{
        std::byte{0x0F}, std::byte{0x28}, std::byte{0xB4},
        std::byte{0x24}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x10}, std::byte{0x00}, // movaps xmm6, [rsp+0x100000]
        std::byte{0x48}, std::byte{0x83}, std::byte{0xC4},
        std::byte{0x28}, std::byte{0xC3}};
    std::memcpy(code + target_offset + prologue.size(),
                epilogue.data(), epilogue.size());

    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 32u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = static_cast<UCHAR>(prologue.size());
    source_info->count_of_codes = 4u;
    set_test_unwind_code(
        source_info, 0u,
        {12u, static_cast<UCHAR>(9u | (6u << 4u))}); // UWOP_SAVE_XMM128_FAR XMM6
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    kTestUnwindCodeOffset + sizeof(TestUnwindCode),
                &save_offset, sizeof(save_offset));
    set_test_unwind_code(
        source_info, 3u, {4u, static_cast<UCHAR>(2u | (4u << 4u))}); // UWOP_ALLOC_SMALL, 0x28 bytes
    

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
    source_table.entry.EndAddress = static_cast<DWORD>(target_offset + 64u);
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
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());

    const NativeHookFn trampoline = hook->original();
    REQUIRE(trampoline != nullptr);
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
        &image_base,
        nullptr);
    REQUIRE(trampoline_function != nullptr);

    std::vector<std::byte> fake_stack(3u * 1024u * 1024u);
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + 0x200008u;
    const auto current_stack_pointer = entry_stack_pointer - stack_allocation;
    const DWORD64 return_address =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    std::memcpy(reinterpret_cast<void*>(entry_stack_pointer),
                &return_address, sizeof(return_address));
    std::array<std::byte, 16> expected_xmm6{};
    for (std::size_t index = 0; index < expected_xmm6.size(); ++index) {
        expected_xmm6[index] = static_cast<std::byte>(index + 0x70u);
    }
    std::memcpy(reinterpret_cast<void*>(current_stack_pointer + save_offset),
                expected_xmm6.data(), expected_xmm6.size());

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = static_cast<DWORD64>(
        reinterpret_cast<std::uintptr_t>(trampoline) +
        kTestTrampolineEntryPrefixSize + prologue.size());
    context.Rsp = static_cast<DWORD64>(current_stack_pointer);
    std::memset(&context.Xmm6, 0, sizeof(context.Xmm6));
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    (void)::RtlVirtualUnwind(
        UNW_FLAG_NHANDLER, image_base, context.Rip, trampoline_function,
        &context, &handler_data, &establisher_frame, nullptr);

    REQUIRE(context.Rip == return_address);
    REQUIRE(context.Rsp == entry_stack_pointer + sizeof(DWORD64));
    REQUIRE(std::memcmp(&context.Xmm6, expected_xmm6.data(),
                        expected_xmm6.size()) == 0);
    REQUIRE(hook->remove().has_value());
}

TEST_CASE("Native x64 trampoline maps UWOP_PUSH_MACHFRAME with and without error code",
          "[hook][native][unwind][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64u;
    constexpr std::size_t source_unwind_offset = 256u;
    auto* source_info =
        reinterpret_cast<TestUnwindInfo*>(code + source_unwind_offset);
    std::memset(source_info, 0, 16u);
    source_info->version_and_flags = 1u;
    source_info->size_of_prolog = 1u;
    source_info->count_of_codes = 1u;
    source_info->frame_register_and_offset = 0u;
    set_test_unwind_code(source_info, 0u, {1u, 10u});

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
    source_table.entry.EndAddress = static_cast<DWORD>(target_offset + 64u);
    source_table.entry.UnwindData = static_cast<DWORD>(source_unwind_offset);
    REQUIRE(::RtlAddFunctionTable(
        &source_table.entry,
        1u,
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(region.address))));
    source_table.registered = true;

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(code + target_offset))},
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    alignas(16) std::array<std::byte, 512> fake_stack{};
    const auto stack_begin = reinterpret_cast<std::uintptr_t>(fake_stack.data());
    const DWORD64 expected_rip =
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(&native_hook_detour));
    const DWORD64 expected_rsp = static_cast<DWORD64>(stack_begin + 384u);

    for (unsigned int has_error_code = 0u; has_error_code <= 1u; ++has_error_code) {
        set_test_unwind_code(
            source_info, 0u,
            {1u, static_cast<UCHAR>(10u | (has_error_code << 4u))});
        REQUIRE(hook->install(options).has_value());

        const NativeHookFn trampoline = hook->original();
        REQUIRE(trampoline != nullptr);
        DWORD64 image_base = 0;
        PRUNTIME_FUNCTION trampoline_function = ::RtlLookupFunctionEntry(
            static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(trampoline)),
            &image_base,
            nullptr);
        REQUIRE(trampoline_function != nullptr);

        const auto frame_address = stack_begin + 64u;
        if (has_error_code == 0u) {
            const std::array<DWORD64, 5> machine_frame{
                expected_rip, 0x10u, 0x202u, expected_rsp, 0x18u};
            std::memcpy(reinterpret_cast<void*>(frame_address),
                        machine_frame.data(), sizeof(machine_frame));
        } else {
            const std::array<DWORD64, 6> machine_frame{
                0xBADC0DEu, expected_rip, 0x10u, 0x202u, expected_rsp, 0x18u};
            std::memcpy(reinterpret_cast<void*>(frame_address),
                        machine_frame.data(), sizeof(machine_frame));
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = static_cast<DWORD64>(
            reinterpret_cast<std::uintptr_t>(trampoline) +
            kTestTrampolineEntryPrefixSize + 1u);
        context.Rsp = static_cast<DWORD64>(frame_address);
        PVOID handler_data = nullptr;
        DWORD64 establisher_frame = 0;
        (void)::RtlVirtualUnwind(
            UNW_FLAG_NHANDLER, image_base, context.Rip, trampoline_function,
            &context, &handler_data, &establisher_frame, nullptr);

        REQUIRE(context.Rip == expected_rip);
        REQUIRE(context.Rsp == expected_rsp);
        REQUIRE(hook->remove().has_value());
    }
}

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

TEST_CASE("Native x64 unwind rejects unsupported, malformed, and prefix-boundary source metadata",
          "[hook][native][unwind][validation][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::array<std::size_t, 6> target_offsets{64u, 128u, 192u, 256u, 320u, 384u};
    constexpr std::array<std::size_t, 6> unwind_offsets{512u, 528u, 544u, 560u, 576u, 592u};
    std::array<std::array<std::byte, 8>, 6> original{};
    for (std::size_t index = 0; index < target_offsets.size(); ++index) {
        const std::size_t offset = target_offsets[index];
        code[offset + 0u] = std::byte{0x48};
        code[offset + 1u] = std::byte{0x83};
        code[offset + 2u] = std::byte{0xEC};
        code[offset + 3u] = std::byte{0x28}; // sub rsp, 0x28
        code[offset + 4u] = std::byte{0x90};

        auto* unwind_info =
            reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[index]);
        std::memset(unwind_info, 0, 16u);
        unwind_info->version_and_flags = 1u;
        unwind_info->size_of_prolog = 4u;
        unwind_info->count_of_codes = 1u;
        unwind_info->frame_register_and_offset = 0u;
        set_test_unwind_code(
            unwind_info, 0u,
            {4u, static_cast<UCHAR>(kTestUnwindOpAllocSmall | (4u << 4u))});
    }

    // The fourth source has an ENDBR64 prefix followed by SUB RSP. Its invalid
    // unwind metadata claims the allocation completed at CodeOffset 4, which
    // is the end of ENDBR64 and before the stack-changing instruction.
    const std::size_t endbr_target = target_offsets[3];
    code[endbr_target + 0u] = std::byte{0xF3};
    code[endbr_target + 1u] = std::byte{0x0F};
    code[endbr_target + 2u] = std::byte{0x1E};
    code[endbr_target + 3u] = std::byte{0xFA};
    code[endbr_target + 4u] = std::byte{0x48};
    code[endbr_target + 5u] = std::byte{0x83};
    code[endbr_target + 6u] = std::byte{0xEC};
    code[endbr_target + 7u] = std::byte{0x28};
    auto* endbr_unwind =
        reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[3]);
    endbr_unwind->size_of_prolog = 8u;
    set_test_unwind_code(endbr_unwind, 0u,
                          {4u, static_cast<UCHAR>(kTestUnwindOpAllocSmall | (4u << 4u))});

    // Version 2 and reserved version-1 opcodes are not copied by this backend.
    reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[4])->version_and_flags = 2u;
    set_test_unwind_code(
        reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[5]),
        0u, {4u, 6u});

    for (std::size_t index = 0; index < target_offsets.size(); ++index) {
        std::memcpy(original[index].data(), code + target_offsets[index],
                    original[index].size());
    }

    // EHANDLER and CHAININFO must be rejected before reading/using their
    // handler-specific or chained payloads as if they were position-independent.
    reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[0])->version_and_flags =
        static_cast<UCHAR>(1u | (1u << 3u));
    reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[1])->version_and_flags =
        static_cast<UCHAR>(1u | (4u << 3u));
    // A valid v1 record whose CodeOffset lands inside the four-byte SUB
    // instruction, not at its end, must also fail closed.
    set_test_unwind_code(
        reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[2]),
        0u, {2u, static_cast<UCHAR>(kTestUnwindOpAllocSmall | (4u << 4u))});

    struct SourceFunctionTableGuard {
        std::array<RUNTIME_FUNCTION, 6> entries{};
        bool registered = false;
        ~SourceFunctionTableGuard() noexcept {
            if (registered && !::RtlDeleteFunctionTable(entries.data())) {
                std::terminate();
            }
        }
    } source_table;
    for (std::size_t index = 0; index < target_offsets.size(); ++index) {
        source_table.entries[index].BeginAddress =
            static_cast<DWORD>(target_offsets[index]);
        source_table.entries[index].EndAddress =
            static_cast<DWORD>(target_offsets[index] + 32u);
        source_table.entries[index].UnwindData =
            static_cast<DWORD>(unwind_offsets[index]);
    }
    REQUIRE(::RtlAddFunctionTable(
        source_table.entries.data(),
        static_cast<DWORD>(source_table.entries.size()),
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(region.address))));
    source_table.registered = true;

    DWORD old_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &old_protection));

    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    for (std::size_t index = 0; index < target_offsets.size(); ++index) {
        auto hook = Hook<NativeHookFn>::create(
            Address{static_cast<std::uint64_t>(
                reinterpret_cast<std::uintptr_t>(code + target_offsets[index]))},
            &native_hook_detour,
            &backend);
        REQUIRE(hook.has_value());
        const auto install = hook->install(options);
        REQUIRE_FALSE(install.has_value());
        REQUIRE(install.error().code == ErrorCode::UnsupportedInstruction);
        REQUIRE_FALSE(hook->installed());
        REQUIRE(std::memcmp(code + target_offsets[index],
                            original[index].data(),
                            original[index].size()) == 0);
    }
}
#endif

