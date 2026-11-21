#include "patch_hook_test_support.hpp"
#include "hook/backends/native_unwind.hpp"


#if defined(_M_X64) || defined(__x86_64__)
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

#endif

#if defined(_M_X64) || defined(__x86_64__)
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
