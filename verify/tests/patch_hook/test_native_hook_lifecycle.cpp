#include "patch_hook_test_support.hpp"

TEST_CASE("Native inline backend rejects modified detach thread policy",
          "[hook][native][validation][threads]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    code[64] = std::byte{0xB8};
    const std::uint32_t return_value = 42;
    std::memcpy(code + 65, &return_value, sizeof(return_value));
    code[69] = std::byte{0xC3};

    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &previous_protection));

    HookOptions options{}; // Strict thread policy is the default.
    HookBackend& backend = native_inline_hook_backend();
    auto attached = backend.attach(
        Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(code + 64))},
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(&native_hook_detour)),
        options);
    REQUIRE(attached.has_value());

    HookToken token = std::move(*attached);
    const auto installed_policy = token.threads;
    REQUIRE(installed_policy == ThreadPolicy::SuspendOthersStrict);
    REQUIRE(token.backend_data != nullptr);
    REQUIRE(code[64] == std::byte{0xE9});

    // A public token must not be able to weaken the thread-suspension policy
    // that was chosen when the patch was installed.
    token.threads = ThreadPolicy::None;
    const auto weakened_detach = backend.detach(token);
    REQUIRE_FALSE(weakened_detach.has_value());
    REQUIRE(weakened_detach.error().code == ErrorCode::Conflict);
    REQUIRE(token.backend_data != nullptr);
    REQUIRE(code[64] == std::byte{0xE9});

    token.threads = installed_policy;
    REQUIRE(backend.detach(token).has_value());
    REQUIRE(token.backend_data == nullptr);
    REQUIRE(code[64] == std::byte{0xB8});
    REQUIRE(code[69] == std::byte{0xC3});
}

TEST_CASE("Native inline backend rejects invalid thread policies without changing hook state",
          "[hook][native][validation][threads]") {
    using namespace tessera;

    HookOptions invalid_options{};
    invalid_options.threads = static_cast<ThreadPolicy>(0xFF);

    // The backend must reject an unknown policy before probing either address.
    const auto invalid_attach = native_inline_hook_backend().attach(
        Address{1}, reinterpret_cast<void*>(static_cast<std::uintptr_t>(2)), invalid_options);
    REQUIRE_FALSE(invalid_attach.has_value());
    REQUIRE(invalid_attach.error().code == ErrorCode::InvalidArgument);

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    code[64] = std::byte{0xB8};
    const std::uint32_t return_value = 42;
    std::memcpy(code + 65, &return_value, sizeof(return_value));
    code[69] = std::byte{0xC3};

    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &previous_protection));

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    HookBackend& backend = native_inline_hook_backend();
    auto attached = backend.attach(
        Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(code + 64))},
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(&native_hook_detour)),
        options);
    REQUIRE(attached.has_value());

    struct TokenGuard {
        HookBackend& backend;
        HookToken token;

        ~TokenGuard() noexcept {
            token.threads = ThreadPolicy::None;
            if (token.backend_data != nullptr) {
                (void)backend.detach(token);
            }
        }
    } guarded{backend, std::move(*attached)};

#if defined(_M_X64) || defined(__x86_64__)
    void* const registered_trampoline = guarded.token.trampoline;
    DWORD64 registered_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(registered_trampoline)),
                &registered_image_base,
                nullptr) != nullptr);
#endif

    guarded.token.threads = static_cast<ThreadPolicy>(0xFF);
    const auto invalid_detach = backend.detach(guarded.token);
    REQUIRE_FALSE(invalid_detach.has_value());
    REQUIRE(invalid_detach.error().code == ErrorCode::InvalidArgument);
    REQUIRE(code[64] == std::byte{0xE9});

    // The rejected detach leaves the original token valid for a correct retry.
    guarded.token.threads = ThreadPolicy::None;
    REQUIRE(backend.detach(guarded.token).has_value());
    REQUIRE(guarded.token.backend_data == nullptr);
    REQUIRE(code[64] == std::byte{0xB8});
    REQUIRE(code[69] == std::byte{0xC3});
#if defined(_M_X64) || defined(__x86_64__)
    DWORD64 removed_image_base = 0;
    REQUIRE(::RtlLookupFunctionEntry(
                static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(registered_trampoline)),
                &removed_image_base,
                nullptr) == nullptr);
#endif

#if defined(_M_X64) || defined(__x86_64__)
    // A dynamically allocated function with a stack-changing prologue but no
    // registered source unwind record must fail before its entry bytes change.
    DWORD writable_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READWRITE,
                             &writable_protection));
    code[256] = std::byte{0x48}; // sub rsp, 0x28
    code[257] = std::byte{0x83};
    code[258] = std::byte{0xEC};
    code[259] = std::byte{0x28};
    code[260] = std::byte{0x90};
    std::array<std::byte, 8> stack_prologue_before{};
    std::memcpy(stack_prologue_before.data(), code + 256, stack_prologue_before.size());
    DWORD read_execute_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ,
                             &read_execute_protection));
    auto unsupported_leaf = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(code + 256))},
        &native_hook_detour,
        &backend);
    REQUIRE(unsupported_leaf.has_value());
    const auto unsupported_leaf_status = unsupported_leaf->install(options);
    REQUIRE_FALSE(unsupported_leaf_status.has_value());
    REQUIRE(unsupported_leaf_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 256, stack_prologue_before.data(),
                        stack_prologue_before.size()) == 0);
#endif
}

#if defined(_M_X64) || defined(__x86_64__)
TEST_CASE("Native x64 unwind rejects a stolen patch that crosses the source function end",
          "[hook][native][unwind][rejection]") {
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
    source_table.entry.EndAddress = static_cast<DWORD>(target_offset + 4u);
    source_table.entry.UnwindData = static_cast<DWORD>(source_unwind_offset);
    REQUIRE(::RtlAddFunctionTable(
        &source_table.entry,
        1u,
        static_cast<DWORD64>(reinterpret_cast<std::uintptr_t>(region.address))));
    source_table.registered = true;

    DWORD old_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &old_protection));

    std::array<std::byte, 8> original_bytes{};
    std::memcpy(original_bytes.data(), code + target_offset, original_bytes.size());

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(code + target_offset))},
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(original_bytes.data(), code + target_offset,
                        original_bytes.size()) == 0);
}

TEST_CASE("Native x64 unwind rejects an unreadable extra unwind-code slot without faulting",
          "[hook][native][unwind][rejection]") {
    using namespace tessera;

    constexpr std::size_t page_size = 4096u;
    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, page_size * 2u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, page_size);

    constexpr std::size_t target_offset = 64u;
    constexpr std::size_t source_unwind_offset = page_size - 4u;
    auto* source_info =
        reinterpret_cast<UCHAR*>(code + source_unwind_offset);
    source_info[0] = 1u; // UNWIND_INFO version 1, no flags
    source_info[1] = 1u; // SizeOfProlog
    source_info[2] = 1u; // One unwind-code slot follows the four-byte header
    source_info[3] = 0u; // No frame register

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

    DWORD first_page_protection = 0;
    DWORD second_page_protection = 0;
    REQUIRE(::VirtualProtect(code, page_size, PAGE_EXECUTE_READ,
                             &first_page_protection));
    REQUIRE(::VirtualProtect(code + page_size, page_size, PAGE_NOACCESS,
                             &second_page_protection));

    std::array<std::byte, 8> original_bytes{};
    std::memcpy(original_bytes.data(), code + target_offset, original_bytes.size());

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(code + target_offset))},
        &native_hook_detour,
        &backend);
    REQUIRE(hook.has_value());
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(original_bytes.data(), code + target_offset,
                        original_bytes.size()) == 0);

    DWORD restored_protection = 0;
    REQUIRE(::VirtualProtect(code + page_size, page_size, PAGE_READWRITE,
                             &restored_protection));
}

#endif // x64 source-range rejection tests

TEST_CASE("Strict thread enumeration ignores a stale Win32 last-error value",
          "[hook][native][threads][integration]") {
    using tessera::ThreadPolicy;
    using tessera::platform::windows::ScopedThreadList;

    ::SetLastError(ERROR_ACCESS_DENIED);
    auto threads = ScopedThreadList::collect_other_threads(
        ThreadPolicy::SuspendOthersStrict);
    REQUIRE(threads.has_value());
}

TEST_CASE("Native inline backend suspends and resumes a real worker thread under strict policy",
          "[hook][native][threads][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    code[64] = std::byte{0xB8};
    const std::uint32_t return_value = 42;
    std::memcpy(code + 65, &return_value, sizeof(return_value));
    code[69] = std::byte{0xC3};

    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &previous_protection));

    WaitingWorkerGuard worker{};
    REQUIRE(worker.wait_until_ready());

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::SuspendOthersStrict;
    REQUIRE(hook->install(options).has_value());
    g_native_hook_original = hook->original();
    REQUIRE(reinterpret_cast<NativeHookFn>(base + 64)(5) == 142);
    REQUIRE(hook->remove().has_value());
    g_native_hook_original = nullptr;

    // The worker was suspended/resumed by both transactions and must still be
    // able to wake, return, and signal its thread object as terminated.
    REQUIRE(worker.finish());
}


TEST_CASE("Native inline backend supports admission-gated concurrent callers across repeated attach and detach",
          "[hook][native][threads][lifecycle][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    code[64] = std::byte{0xF3};
    code[65] = std::byte{0x0F};
    code[66] = std::byte{0x1E};
#if defined(_M_X64) || defined(__x86_64__)
    code[67] = std::byte{0xFA}; // ENDBR64
#else
    code[67] = std::byte{0xFB}; // ENDBR32
#endif
    code[68] = std::byte{0xB8}; // mov eax, 42
    const std::uint32_t return_value = 42;
    std::memcpy(code + 69, &return_value, sizeof(return_value));
    code[73] = std::byte{0xC3}; // ret

    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(region.address, 4096, PAGE_EXECUTE_READ, &previous_protection));

    const auto target = reinterpret_cast<NativeHookFn>(code + 64);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(target, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    // This shared/exclusive gate models the application-level admission and
    // drain contract: all target and trampoline calls hold a shared lease,
    // while install/remove take the exclusive lease before patching.
    std::shared_mutex admission_gate;
    std::atomic<std::uint64_t> unhooked_calls{0};
    std::atomic<std::uint64_t> hooked_calls{0};
    std::atomic<std::uint64_t> unexpected_results{0};
    std::vector<std::jthread> workers;
    constexpr std::size_t kWorkerCount = 4;
    for (std::size_t index = 0; index < kWorkerCount; ++index) {
        workers.emplace_back([&](std::stop_token stop_token) {
            while (!stop_token.stop_requested()) {
                std::shared_lock admission_lock(admission_gate);
                if (stop_token.stop_requested()) {
                    break;
                }

                const int result = target(5);
                if (result == 42) {
                    unhooked_calls.fetch_add(1, std::memory_order_relaxed);
                } else if (result == 142) {
                    hooked_calls.fetch_add(1, std::memory_order_relaxed);
                } else {
                    unexpected_results.fetch_add(1, std::memory_order_relaxed);
                }
                std::this_thread::yield();
            }
        });
    }

    const auto wait_for_count = [](const std::atomic<std::uint64_t>& counter,
                                   std::uint64_t expected) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (counter.load(std::memory_order_acquire) < expected &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        return counter.load(std::memory_order_acquire) >= expected;
    };

    REQUIRE(wait_for_count(unhooked_calls, 32));

    HookOptions options{};
    options.threads = ThreadPolicy::SuspendOthersStrict;
    constexpr int kInstallRemoveCycles = 4;
    for (int cycle = 0; cycle < kInstallRemoveCycles; ++cycle) {
        std::uint64_t hooked_goal = 0;
        {
            std::unique_lock admission_lock(admission_gate);
            REQUIRE(hook->install(options).has_value());
            g_native_hook_original = hook->original();
            hooked_goal = hooked_calls.load(std::memory_order_acquire) + 32;
        }
        REQUIRE(wait_for_count(hooked_calls, hooked_goal));

        std::uint64_t unhooked_goal = 0;
        {
            std::unique_lock admission_lock(admission_gate);
            REQUIRE(hook->remove().has_value());
            g_native_hook_original = nullptr;
            unhooked_goal = unhooked_calls.load(std::memory_order_acquire) + 32;
        }
        REQUIRE(wait_for_count(unhooked_calls, unhooked_goal));
    }

    for (auto& worker : workers) {
        worker.request_stop();
    }
    workers.clear(); // jthread joins before the executable region is released.

    REQUIRE(unexpected_results.load(std::memory_order_acquire) == 0);
    REQUIRE(hooked_calls.load(std::memory_order_acquire) >=
            static_cast<std::uint64_t>(kInstallRemoveCycles * 32));
    REQUIRE(target(5) == 42);
    REQUIRE(code[64] == std::byte{0xF3});
    REQUIRE(code[65] == std::byte{0x0F});
    REQUIRE(code[66] == std::byte{0x1E});
#if defined(_M_X64) || defined(__x86_64__)
    REQUIRE(code[67] == std::byte{0xFA});
#else
    REQUIRE(code[67] == std::byte{0xFB});
#endif
    REQUIRE(code[68] == std::byte{0xB8});
    REQUIRE(code[73] == std::byte{0xC3});
}

#if defined(TESSERA_TEST_WITH_DETOURS)

TEST_CASE("Native hook host admission drains active detours before unloading the detour module",
          "[hook][native][lifecycle][module][integration]") {
    using namespace tessera;

#if !defined(TESSERA_HOOK_MODULE_FIXTURE_PATH)
    FAIL("The native hook module fixture path was not configured by CMake.");
#else
    struct ModuleGuard {
        HMODULE module = nullptr;
        bool safe_to_unload = true;

        ~ModuleGuard() noexcept {
            // If detach could not be proven successful, deliberately retain the
            // module until process exit rather than unload live detour code.
            if (module != nullptr && safe_to_unload) {
                (void)::FreeLibrary(module);
            }
        }

        [[nodiscard]] bool unload() noexcept {
            if (module == nullptr) {
                return true;
            }
            if (!::FreeLibrary(module)) {
                return false;
            }
            module = nullptr;
            return true;
        }
    } module{
        ::LoadLibraryA(TESSERA_HOOK_MODULE_FIXTURE_PATH), true};
    REQUIRE(module.module != nullptr);

    const auto find_export = [](HMODULE handle, const char* name) noexcept -> FARPROC {
        FARPROC symbol = ::GetProcAddress(handle, name);
#if defined(_M_IX86)
        if (symbol == nullptr) {
            std::array<char, 128> decorated{};
            const std::size_t length = std::strlen(name);
            if (length + 2u <= decorated.size()) {
                decorated[0] = '_';
                std::memcpy(decorated.data() + 1u, name, length + 1u);
                symbol = ::GetProcAddress(handle, decorated.data());
            }
        }
#endif
        return symbol;
    };
    const auto resolve_export = [&find_export]<typename Fn>(
                                    HMODULE handle,
                                    const char* name) noexcept -> Fn {
        const FARPROC symbol = find_export(handle, name);
        Fn function = nullptr;
        static_assert(sizeof(function) == sizeof(symbol),
                      "Windows function pointers and FARPROC must have equal size");
        std::memcpy(&function, &symbol, sizeof(function));
        return function;
    };

    using ConfigureFn = void(__cdecl*)(NativeHookFn, HANDLE, HANDLE);
    using ActiveCallsFn = LONG(__cdecl*)();
    const auto configure = resolve_export.template operator()<ConfigureFn>(
        module.module, "tessera_fixture_configure");
    const auto active_calls = resolve_export.template operator()<ActiveCallsFn>(
        module.module, "tessera_fixture_active_calls");
    const auto detour = resolve_export.template operator()<NativeHookFn>(
        module.module, "tessera_fixture_detour");
    REQUIRE(configure != nullptr);
    REQUIRE(active_calls != nullptr);
    REQUIRE(detour != nullptr);

    struct EventGuard {
        HANDLE handle = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ~EventGuard() noexcept {
            if (handle != nullptr) {
                (void)::CloseHandle(handle);
            }
        }
    } entered_event, release_event;
    REQUIRE(entered_event.handle != nullptr);
    REQUIRE(release_event.handle != nullptr);

    HookBackend& backend = native_inline_hook_backend();
    NativeHookFn volatile target_entry = &native_hook_target;
    auto hook = Hook<NativeHookFn>::create(
        target_entry,
        detour,
        &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    module.safe_to_unload = false;
    configure(hook->original(), entered_event.handle, release_event.handle);

    std::shared_mutex admission_gate;
    std::atomic<int> call_result{-1};
    struct JoiningCall {
        HANDLE release_event = nullptr;
        std::thread worker{};

        ~JoiningCall() noexcept {
            if (worker.joinable()) {
                if (release_event != nullptr) {
                    (void)::SetEvent(release_event);
                }
                worker.join();
            }
        }
    } caller{release_event.handle};

    caller.worker = std::thread([&] {
        std::shared_lock admission(admission_gate);
        call_result.store(target_entry(5), std::memory_order_release);
    });

    REQUIRE(::WaitForSingleObject(entered_event.handle, 5000) == WAIT_OBJECT_0);
    REQUIRE(active_calls() == 1);

    // The callback is blocked inside the DLL. The host's exclusive admission
    // gate cannot be acquired, so neither detach nor FreeLibrary is permitted.
    std::unique_lock stop_admission(admission_gate, std::defer_lock);
    REQUIRE_FALSE(stop_admission.try_lock());
    REQUIRE(::GetModuleHandleA("tessera_hook_module_fixture.dll") == module.module);

    REQUIRE(::SetEvent(release_event.handle));
    caller.worker.join();
    REQUIRE(call_result.load(std::memory_order_acquire) == 1103);
    REQUIRE(active_calls() == 0);
    REQUIRE(stop_admission.try_lock());

    // No new caller can enter while this exclusive gate is held. Successful
    // detach must precede unloading the module that supplied the detour.
    REQUIRE(hook->remove().has_value());
    REQUIRE_FALSE(hook->installed());
    module.safe_to_unload = true;
    REQUIRE(module.unload());
    REQUIRE(::GetModuleHandleA("tessera_hook_module_fixture.dll") == nullptr);

    // The original target remains callable after its detour module is gone.
    REQUIRE(target_entry(5) == 103);
#endif
}

TEST_CASE("Microsoft Detours performs a live attach, trampoline call, and detach", "[hook][detours]") {
    using namespace tessera;

    auto hook = Hook<LiveHookFn>::create(&live_hook_target, &live_hook_detour);
    REQUIRE(hook.has_value());

    // Indirect volatile call prevents the compiler from bypassing the patched entry point.
    LiveHookFn volatile entry = &live_hook_target;
    REQUIRE(entry(5) == 15);

    HookOptions options{};
    // This test is single-threaded and only exercises the current test thread.
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    REQUIRE(hook->installed());

    g_live_hook_original = hook->original();
    REQUIRE(g_live_hook_original != nullptr);
    REQUIRE(entry(5) == 115);

    REQUIRE(hook->remove().has_value());
    REQUIRE_FALSE(hook->installed());
    g_live_hook_original = nullptr;
    REQUIRE(entry(5) == 15);
}

TEST_CASE("Microsoft Detours performs attach and detach with strict worker-thread enlistment",
          "[hook][detours][threads][integration]") {
    using namespace tessera;

    auto hook = Hook<LiveHookFn>::create(&live_hook_target, &live_hook_detour);
    REQUIRE(hook.has_value());

    LiveHookFn volatile entry = &live_hook_target;
    REQUIRE(entry(5) == 15);

    WaitingWorkerGuard worker{};
    REQUIRE(worker.wait_until_ready());

    HookOptions options{};
    options.threads = ThreadPolicy::SuspendOthersStrict;
    REQUIRE(hook->install(options).has_value());

    g_live_hook_original = hook->original();
    REQUIRE(g_live_hook_original != nullptr);
    REQUIRE(entry(5) == 115);

    REQUIRE(hook->remove().has_value());
    g_live_hook_original = nullptr;
    REQUIRE(entry(5) == 15);
    REQUIRE(worker.finish());
}
#endif


namespace {

struct FakePatchWriteOps {
    std::vector<bool> protect_results;
    std::vector<bool> flush_results;
    std::vector<unsigned long> protect_errors;
    std::vector<unsigned long> flush_errors;
    std::size_t protect_index = 0;
    std::size_t flush_index = 0;
    std::size_t copy_calls = 0;
    std::vector<char> events;
    unsigned long error = 1234;
    unsigned long current_protection = 0x20UL;
    unsigned long writable_protection = 0x40UL;
    bool copied_without_write_access = false;

    bool protect(void*, std::size_t, unsigned long requested, unsigned long* previous) {
        const std::size_t call_index = protect_index++;
        const bool result = call_index < protect_results.size()
                                ? protect_results[call_index]
                                : true;
        events.push_back(result ? 'P' : 'p');
        if (result) {
            if (previous != nullptr) {
                *previous = current_protection;
            }
            current_protection = requested;
        } else {
            error = call_index < protect_errors.size()
                        ? protect_errors[call_index]
                        : 5678UL;
        }
        return result;
    }

    void copy(void* target, const std::byte* source, std::size_t size) {
        events.push_back('C');
        ++copy_calls;
        copied_without_write_access |= current_protection != writable_protection;
        std::memcpy(target, source, size);
    }

    bool flush(void*, std::size_t) {
        const std::size_t call_index = flush_index++;
        const bool result = call_index < flush_results.size()
                                ? flush_results[call_index]
                                : true;
        events.push_back(result ? 'F' : 'f');
        if (!result) {
            error = call_index < flush_errors.size()
                        ? flush_errors[call_index]
                        : 9012UL;
        }
        return result;
    }

    unsigned long last_error() const noexcept { return error; }
};

} // namespace

