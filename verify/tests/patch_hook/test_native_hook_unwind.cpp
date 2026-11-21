#include "patch_hook_test_support.hpp"
#include "hook/backends/native_unwind.hpp"


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

#endif
