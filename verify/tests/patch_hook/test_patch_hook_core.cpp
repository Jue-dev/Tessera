#include "patch_hook_test_support.hpp"

TEST_CASE("Native hook address range helpers remain correct at uintptr limits",
          "[hook][native][address-range]") {
    using tessera::detail::address_range_contains;
    using tessera::detail::address_ranges_overlap;

    constexpr std::uintptr_t maximum =
        (std::numeric_limits<std::uintptr_t>::max)();

    REQUIRE(address_ranges_overlap(maximum - 7u, 8u, maximum - 2u, 2u));
    REQUIRE(address_ranges_overlap(maximum - 2u, 2u, maximum - 7u, 8u));
    REQUIRE_FALSE(address_ranges_overlap(maximum - 7u, 4u, maximum - 2u, 2u));
    REQUIRE_FALSE(address_ranges_overlap(maximum, 0u, maximum, 1u));
    REQUIRE_FALSE(address_ranges_overlap(maximum, 1u, maximum, 0u));

    REQUIRE(address_range_contains(maximum - 2u, 3u, maximum - 2u));
    REQUIRE(address_range_contains(maximum - 2u, 3u, maximum));
    REQUIRE_FALSE(address_range_contains(maximum - 2u, 2u, maximum));
    REQUIRE_FALSE(address_range_contains(maximum, 0u, maximum));
    REQUIRE(address_range_contains(1u, (std::numeric_limits<std::size_t>::max)(), maximum));
}


TEST_CASE("Tessera's bounded x86/x64 decoder reports instruction and relocation metadata",
          "[hook][native][decoder]") {
    using namespace tessera::detail::x86;

    const auto decode = [](Mode mode,
                           std::initializer_list<std::uint8_t> encoded) {
        std::array<std::byte, 15> bytes{};
        std::size_t length = 0;
        for (const std::uint8_t value : encoded) {
            if (length >= bytes.size()) break;
            bytes[length++] = static_cast<std::byte>(value);
        }

        DecodedInstruction instruction{};
        const bool succeeded = decode_instruction(bytes.data(), length, mode, instruction);
        return std::pair<bool, DecodedInstruction>{succeeded, instruction};
    };

    const auto endbr64 = decode(Mode::x64, {0xF3, 0x0F, 0x1E, 0xFA});
    REQUIRE(endbr64.first);
    REQUIRE(endbr64.second.length == 4);

    // FEMMS is a two-byte no-ModRM opcode. Decode the following short branch
    // independently so its displacement cannot be absorbed into the first instruction.
    const auto femms = decode(Mode::x86, {0x0F, 0x0E});
    REQUIRE(femms.first);
    REQUIRE(femms.second.length == 2);
    const auto following_jcc = decode(Mode::x86, {0x74, 0x02, 0x90, 0x90});
    REQUIRE(following_jcc.first);
    REQUIRE(following_jcc.second.length == 2);
    REQUIRE(following_jcc.second.has_relative_operand);
    REQUIRE_FALSE(decode(Mode::x86, {0x0F, 0x0C}).first);

    const auto rip_load = decode(Mode::x64, {0x48, 0x8B, 0x05, 0x34, 0x12, 0x00, 0x00});
    REQUIRE(rip_load.first);
    REQUIRE(rip_load.second.length == 7);
    REQUIRE(rip_load.second.has_rip_relative_operand);
    REQUIRE(rip_load.second.rip_displacement_offset == 3);

    const auto near_jcc = decode(Mode::x64, {0x0F, 0x85, 0x01, 0x00, 0x00, 0x00});
    REQUIRE(near_jcc.first);
    REQUIRE(near_jcc.second.length == 6);
    REQUIRE(near_jcc.second.has_relative_operand);
    REQUIRE(near_jcc.second.relative_offset == 2);
    REQUIRE(near_jcc.second.relative_size == 4);

    const auto stack_adjust = decode(Mode::x64, {0x48, 0x81, 0xEC, 0x20, 0x00, 0x00, 0x00});
    REQUIRE(stack_adjust.first);
    REQUIRE(stack_adjust.second.length == 7);

    const auto rex_w_adjust = decode(
        Mode::x64, {0x66, 0x48, 0x81, 0xEC, 0x08, 0x00, 0x00, 0x00});
    REQUIRE(rex_w_adjust.first);
    REQUIRE(rex_w_adjust.second.length == 8);

    const auto movabs = decode(
        Mode::x64, {0x48, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
    REQUIRE(movabs.first);
    REQUIRE(movabs.second.length == 10);

    const auto xbegin = decode(Mode::x64, {0xC7, 0xF8, 0x01, 0x00, 0x00, 0x00});
    REQUIRE(xbegin.first);
    REQUIRE(xbegin.second.length == 6);
    REQUIRE(xbegin.second.has_relative_operand);
    REQUIRE(xbegin.second.relative_offset == 2);
    REQUIRE(xbegin.second.relative_size == 4);

    const auto immediate_store = decode(Mode::x64, {0xC6, 0x44, 0x24, 0x08, 0x01});
    REQUIRE(immediate_store.first);
    REQUIRE(immediate_store.second.length == 5);

    // A 66 prefix does not turn a long-mode near CALL into rel16.
    const auto prefixed_call = decode(Mode::x64, {0x66, 0xE8, 0x00, 0x00, 0x00, 0x00});
    REQUIRE(prefixed_call.first);
    REQUIRE(prefixed_call.second.length == 6);
    REQUIRE(prefixed_call.second.relative_size == 4);

    const auto address16 = decode(Mode::x86, {0x67, 0x8B, 0x06, 0x34, 0x12});
    REQUIRE(address16.first);
    REQUIRE(address16.second.length == 5);

    const auto vex = decode(Mode::x64, {0xC5, 0xF8, 0x77});
    REQUIRE(vex.first);
    REQUIRE(vex.second.length == 3);

    const auto vex_immediate = decode(Mode::x64, {0xC5, 0xF9, 0x70, 0xC0, 0x01});
    REQUIRE(vex_immediate.first);
    REQUIRE(vex_immediate.second.length == 5);

    const auto evex = decode(Mode::x64, {0x62, 0xF1, 0x7C, 0x48, 0x58, 0xC0});
    REQUIRE(evex.first);
    REQUIRE(evex.second.length == 6);

    const auto map3 = decode(Mode::x64, {0x66, 0x0F, 0x3A, 0x0F, 0xC0, 0x08});
    REQUIRE(map3.first);
    REQUIRE(map3.second.length == 6);

    const auto maximum_length = decode(
        Mode::x64,
        {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
         0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90});
    REQUIRE(maximum_length.first);
    REQUIRE(maximum_length.second.length == 15);

    std::array<std::byte, 15> truncated_bytes{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05}};
    DecodedInstruction rejected_metadata{};
    rejected_metadata.length = 99;
    REQUIRE_FALSE(decode_instruction(
        truncated_bytes.data(), 3, Mode::x64, rejected_metadata));
    REQUIRE(rejected_metadata.length == 0);
    REQUIRE_FALSE(rejected_metadata.has_relative_operand);
    REQUIRE_FALSE(rejected_metadata.has_rip_relative_operand);

    const auto overlong = decode(
        Mode::x64,
        {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
         0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66});
    REQUIRE_FALSE(overlong.first);
}


TEST_CASE("Hook callable leases support same-thread recursive original calls",
          "[hook][lifecycle][threads]") {
    using namespace tessera;

    MockHookBackend backend{};
    backend.trampoline = reinterpret_cast<void*>(&recursive_trampoline_function);
    auto hook = Hook<NativeHookFn>::create(
        &sample_target_function, &sample_detour_function, &backend);
    REQUIRE(hook.has_value());
    REQUIRE(hook->install().has_value());

    g_recursive_lease_hook = &*hook;
    const int result = (*hook)(4);
    g_recursive_lease_hook = nullptr;

    REQUIRE(result == 10);
    REQUIRE(hook->remove().has_value());
}


TEST_CASE("Hook lifecycle changes inside a leased call fail without deadlocking",
          "[hook][lifecycle][threads]") {
    using namespace tessera;

    g_remove_from_lease_rejected.store(false, std::memory_order_release);
    g_release_from_lease_rejected.store(false, std::memory_order_release);
    MockHookBackend backend{};
    backend.trampoline = reinterpret_cast<void*>(&remove_from_callable_lease_trampoline);
    auto hook = Hook<NativeHookFn>::create(
        &sample_target_function, &sample_detour_function, &backend);
    REQUIRE(hook.has_value());
    REQUIRE(hook->install().has_value());

    g_recursive_lease_hook = &*hook;
    const int result = (*hook)(5);
    g_recursive_lease_hook = nullptr;

    REQUIRE(result == 12);
    REQUIRE(g_remove_from_lease_rejected.load(std::memory_order_acquire));
    REQUIRE(g_release_from_lease_rejected.load(std::memory_order_acquire));
    REQUIRE(hook->installed());
    REQUIRE(hook->remove().has_value());
}


TEST_CASE("Hook callable leases drain in-flight operator calls before remove",
          "[hook][lifecycle][threads]") {
    using namespace tessera;

    g_callable_lease_entered.store(false, std::memory_order_release);
    g_callable_lease_release.store(false, std::memory_order_release);

    MockHookBackend backend{};
    backend.trampoline = reinterpret_cast<void*>(&blocking_trampoline_function);
    auto hook = Hook<NativeHookFn>::create(
        &sample_target_function, &sample_detour_function, &backend);
    REQUIRE(hook.has_value());
    REQUIRE(hook->install().has_value());

    std::atomic<int> call_result{-1};
    std::atomic<bool> remove_started{false};
    std::atomic<bool> remove_finished{false};
    std::atomic<bool> remove_succeeded{false};

    std::thread caller([&] {
        auto lease = hook->acquire();
        const NativeHookFn callable = lease.get();
        call_result.store(callable != nullptr ? callable(5) : -1, std::memory_order_release);
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
    const bool remove_finished_before_release =
        remove_finished.load(std::memory_order_acquire);

    g_callable_lease_release.store(true, std::memory_order_release);
    caller.join();
    remover.join();

    REQUIRE_FALSE(remove_finished_before_release);
    REQUIRE(remove_succeeded.load(std::memory_order_acquire));
    REQUIRE(remove_finished.load(std::memory_order_acquire));
    REQUIRE(call_result.load(std::memory_order_acquire) == 47);
    REQUIRE_FALSE(hook->installed());
}


TEST_CASE("Hook lifecycle and Detours-off contract", "[hook]") {
    using namespace tessera;

    using FnType = int(__cdecl*)(int);
    using ScopedCallable = Hook<FnType>::ScopedCallable;
    static_assert(!std::is_copy_constructible_v<ScopedCallable>);
    static_assert(!std::is_move_constructible_v<ScopedCallable>);

    auto self_detour = Hook<FnType>::create(
        &sample_target_function, &sample_target_function);
    REQUIRE_FALSE(self_detour.has_value());
    REQUIRE(self_detour.error().code == ErrorCode::InvalidArgument);

    // 1. Default backend selection is available without Microsoft Detours;
    //    original() and operator() are defined immediately after create().
    auto hk_default = Hook<FnType>::create(&sample_target_function, &sample_detour_function);
    REQUIRE(hk_default.has_value());
    REQUIRE_FALSE(hk_default->installed());
    REQUIRE(hk_default->original() != nullptr);
    REQUIRE((*hk_default)(5) == 15);
    {
        auto callable = hk_default->acquire();
        REQUIRE(callable.get() == &sample_target_function);
        REQUIRE(callable.target() == &sample_target_function);
        REQUIRE(callable.get()(5) == 15);
    }

#if defined(TESSERA_TEST_WITH_DETOURS)
    // The Detours-enabled build must link the real backend and report it available.
    // This assertion deliberately avoids modifying executable code in the unit suite.
    REQUIRE(default_hook_backend().available());
#else
    // Detours-off builds use Tessera's native inline backend by default.
    REQUIRE(default_hook_backend().available());
#endif

    // 2. Full lifecycle with MockHookBackend
    MockHookBackend mock_backend{};
    {
        auto hk = Hook<FnType>::create(
            &sample_target_function, &sample_detour_function, &mock_backend);
        REQUIRE(hk.has_value());
        REQUIRE((*hk)(7) == 17);

        REQUIRE(hk->install().has_value());
        REQUIRE(hk->installed());
        REQUIRE(mock_backend.attach_calls == 1);
        REQUIRE((*hk)(7) == 17);
        {
            auto callable = hk->acquire();
            REQUIRE(callable.target() == &sample_target_function);
            REQUIRE(callable.get() == reinterpret_cast<FnType>(&sample_trampoline_function));
            REQUIRE(callable.get()(7) == 17);
        }

        REQUIRE(hk->remove().has_value());
        REQUIRE_FALSE(hk->installed());
        REQUIRE(mock_backend.detach_calls == 1);
        REQUIRE((*hk)(7) == 17);
    }

    // 3. Backend exceptions are translated into Status values without losing
    //    HookCore state. A failed detach remains retryable.
    MockHookBackend throwing_backend{};
    throwing_backend.throw_on_attach = true;
    auto exception_hook = Hook<FnType>::create(
        &sample_target_function, &sample_detour_function, &throwing_backend);
    REQUIRE(exception_hook.has_value());

    const auto throwing_attach = exception_hook->install();
    REQUIRE_FALSE(throwing_attach.has_value());
    REQUIRE(throwing_attach.error().code == ErrorCode::OutOfMemory);
    REQUIRE_FALSE(exception_hook->installed());

    throwing_backend.throw_on_attach = false;
    REQUIRE(exception_hook->install().has_value());
    throwing_backend.throw_on_detach = true;
    const auto throwing_detach = exception_hook->remove();
    REQUIRE_FALSE(throwing_detach.has_value());
    REQUIRE(throwing_detach.error().code == ErrorCode::OutOfMemory);
    REQUIRE(exception_hook->installed());

    throwing_backend.throw_on_detach = false;
    REQUIRE(exception_hook->remove().has_value());
    REQUIRE_FALSE(exception_hook->installed());

    // 4. Move assignment must not orphan an installed hook when detach fails.
    MockHookBackend retained_backend{};
    retained_backend.fail_detach = true;
    MockHookBackend incoming_backend{};
    incoming_backend.trampoline = reinterpret_cast<void*>(&sample_alternate_trampoline_function);
    {
        auto destination = Hook<FnType>::create(
            &sample_target_function, &sample_detour_function, &retained_backend);
        auto incoming = Hook<FnType>::create(
            &sample_target_function, &sample_detour_function, &incoming_backend);
        REQUIRE(destination.has_value());
        REQUIRE(incoming.has_value());
        REQUIRE(destination->install().has_value());
        REQUIRE(incoming->install().has_value());

        *destination = std::move(*incoming);

        REQUIRE(destination->installed());
        REQUIRE(incoming->installed());
        REQUIRE(destination->original() == reinterpret_cast<FnType>(&sample_trampoline_function));
        REQUIRE(incoming->original() == reinterpret_cast<FnType>(&sample_alternate_trampoline_function));
        REQUIRE(retained_backend.detach_calls == 1);
        REQUIRE(incoming_backend.detach_calls == 0);

        // Allow orderly cleanup after verifying that ownership was retained.
        retained_backend.fail_detach = false;
    }

    // Invalid enum values must never silently weaken strict thread coordination.
    MockHookBackend invalid_policy_backend{};
    auto invalid_policy_hook = Hook<FnType>::create(
        &sample_target_function, &sample_detour_function, &invalid_policy_backend);
    REQUIRE(invalid_policy_hook.has_value());
    HookOptions invalid_policy_options{};
    invalid_policy_options.threads = static_cast<ThreadPolicy>(0xFF);
    const auto invalid_policy_status = invalid_policy_hook->install(invalid_policy_options);
    REQUIRE_FALSE(invalid_policy_status.has_value());
    REQUIRE(invalid_policy_status.error().code == ErrorCode::InvalidArgument);
    REQUIRE(invalid_policy_backend.attach_calls == 0);
    REQUIRE_FALSE(invalid_policy_hook->installed());
}


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


TEST_CASE("PatchTransaction does not roll back patches applied before the transaction", "[patch][transaction]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x610000}, 0x1000, MemoryProtection::ReadWrite);
    const std::array<std::byte, 4> original{
        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
    backend->poke_bytes(Address{0x610100}, original);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);

    auto first_result = Patch::nop(ProcessAddress{process, Address{0x610100}}, 4);
    REQUIRE(first_result.has_value());
    Patch first = std::move(*first_result);
    REQUIRE(first.apply().has_value());
    REQUIRE(first.state() == PatchState::Applied);

    PatchTransaction transaction{};
    transaction.add(std::move(first));
    auto second_result = Patch::nop(ProcessAddress{process, Address{0x999000}}, 4);
    REQUIRE(second_result.has_value());
    transaction.add(std::move(*second_result));

    const auto report = transaction.apply();
    REQUIRE_FALSE(report.succeeded);
    REQUIRE_FALSE(report.rolled_back);
    REQUIRE(report.steps[0].state == PatchState::Applied);
    REQUIRE(*backend->peek_byte(Address{0x610100}) == std::byte{0x90});

    REQUIRE(transaction.restore_all().has_value());
    REQUIRE(*backend->peek_byte(Address{0x610100}) == std::byte{0x10});
}
