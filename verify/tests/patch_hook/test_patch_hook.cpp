#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <cstdint>
#include <new>
#include <limits>
#include <initializer_list>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <Windows.h>

#include "FakeMemoryBackend.hpp"
#include "hook/backends/patch_write_transaction.hpp"
#include "hook/backends/address_range.hpp"
#include "platform/windows/thread_backend.hpp"
#include "hook/backends/x86_instruction_decoder.hpp"
#include "tessera/hook/hook.hpp"
#include "tessera/patch/patch.hpp"
#include "tessera/pattern/pattern.hpp"

namespace {

int __cdecl sample_target_function(int x) {
    return x + 10;
}

int __cdecl sample_detour_function(int x) {
    return x + 100;
}

int __cdecl sample_trampoline_function(int x) {
    return x + 10;
}

int __cdecl sample_alternate_trampoline_function(int x) {
    return x + 20;
}

std::atomic<bool> g_callable_lease_entered{false};
std::atomic<bool> g_callable_lease_release{false};

int __cdecl blocking_trampoline_function(int value) {
    g_callable_lease_entered.store(true, std::memory_order_release);
    while (!g_callable_lease_release.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    return value + 42;
}

#if defined(_MSC_VER)
#define TESSERA_TEST_NOINLINE __declspec(noinline)
#elif defined(__clang__) || defined(__GNUC__)
#define TESSERA_TEST_NOINLINE __attribute__((noinline))
#else
#define TESSERA_TEST_NOINLINE
#endif

using NativeHookFn = int(__cdecl*)(int);
using NativeHookFastFn = std::uintptr_t(__fastcall*)(std::uintptr_t);
std::atomic<NativeHookFn> g_lease_detour_original{nullptr};

int __cdecl blocking_lease_detour(int value) {
    const NativeHookFn original =
        g_lease_detour_original.load(std::memory_order_acquire);
    return original != nullptr ? original(value) : -1;
}

#if defined(_M_X64) || defined(__x86_64__)
struct TestUnwindCode {
    UCHAR code_offset = 0;
    UCHAR operation = 0;
};

struct TestUnwindInfo {
    UCHAR version_and_flags = 0;
    UCHAR size_of_prolog = 0;
    UCHAR count_of_codes = 0;
    UCHAR frame_register_and_offset = 0;
    TestUnwindCode unwind_code[1]{};
};

constexpr UCHAR kTestUnwindOpAllocSmall = 2u;
constexpr UCHAR kTestUnwindOpPushNonVol = 0u;
static_assert(offsetof(TestUnwindInfo, unwind_code) == 4u);
static_assert(sizeof(TestUnwindCode) == 2u);
DWORD __cdecl invoke_breakpoint_trampoline(NativeHookFn trampoline) noexcept {
    __try {
        (void)trampoline(0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return ::GetExceptionCode();
    }
    return ERROR_SUCCESS;
}
#endif
tessera::Hook<NativeHookFn>* g_recursive_lease_hook = nullptr;
std::atomic<bool> g_remove_from_lease_rejected{false};
std::atomic<bool> g_release_from_lease_rejected{false};

int __cdecl remove_from_callable_lease_trampoline(int value) {
    const auto result = g_recursive_lease_hook->remove();
    g_remove_from_lease_rejected.store(
        !result.has_value() && result.error().code == tessera::ErrorCode::Conflict,
        std::memory_order_release);
    const NativeHookFn released = g_recursive_lease_hook->release();
    g_release_from_lease_rejected.store(released == nullptr, std::memory_order_release);
    return value + 7;
}

int __cdecl recursive_trampoline_function(int value) {
    if (value <= 0) {
        return 0;
    }
    return value + (*g_recursive_lease_hook)(value - 1);
}

struct ExecutableRegionGuard {
    void* address = nullptr;
    ~ExecutableRegionGuard() noexcept {
        if (address != nullptr) {
            (void)::VirtualFree(address, 0, MEM_RELEASE);
        }
    }
};

volatile int g_native_hook_terms[8] = {3, 5, 7, 11, 13, 17, 19, 23};
NativeHookFn g_native_hook_original = nullptr;

// Volatile global reads deliberately exercise x64 RIP-relative relocation in the
// trampoline, while the function body has a relocatable prologue for the native entry jump.
TESSERA_TEST_NOINLINE int __cdecl native_hook_target(int value) {
    int result = value;
    result += g_native_hook_terms[0];
    result += g_native_hook_terms[1];
    result += g_native_hook_terms[2];
    result += g_native_hook_terms[3];
    result += g_native_hook_terms[4];
    result += g_native_hook_terms[5];
    result += g_native_hook_terms[6];
    result += g_native_hook_terms[7];
    return result;
}

TESSERA_TEST_NOINLINE int __cdecl native_hook_detour(int value) {
    return g_native_hook_original(value) + 100;
}

TESSERA_TEST_NOINLINE std::uintptr_t __fastcall native_hook_fast_detour(std::uintptr_t value) {
    return value + 500;
}

TESSERA_TEST_NOINLINE int __cdecl native_hook_detour_1000(int value) {
    return value + 1000;
}

TESSERA_TEST_NOINLINE int __cdecl native_hook_detour_2000(int value) {
    return value + 2000;
}

TESSERA_TEST_NOINLINE int __cdecl native_hook_detour_3000(int value) {
    return value + 3000;
}

struct WaitingWorkerSignals {
    HANDLE ready = nullptr;
    HANDLE release = nullptr;
};

DWORD WINAPI native_hook_waiting_worker(void* context) {
    auto* signals = static_cast<WaitingWorkerSignals*>(context);
    ::SetEvent(signals->ready);
    (void)::WaitForSingleObject(signals->release, INFINITE);
    return 0;
}

struct WaitingWorkerGuard {
    WaitingWorkerSignals signals{};
    HANDLE thread = nullptr;

    WaitingWorkerGuard() noexcept {
        signals.ready = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        signals.release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (signals.ready != nullptr && signals.release != nullptr) {
            thread = ::CreateThread(nullptr, 0, &native_hook_waiting_worker, &signals, 0, nullptr);
        }
    }

    WaitingWorkerGuard(const WaitingWorkerGuard&) = delete;
    WaitingWorkerGuard& operator=(const WaitingWorkerGuard&) = delete;

    ~WaitingWorkerGuard() noexcept {
        (void)finish();
        if (thread != nullptr) {
            (void)::CloseHandle(thread);
        }
        if (signals.ready != nullptr) {
            (void)::CloseHandle(signals.ready);
        }
        if (signals.release != nullptr) {
            (void)::CloseHandle(signals.release);
        }
    }

    [[nodiscard]] bool wait_until_ready() const noexcept {
        return signals.ready != nullptr && signals.release != nullptr && thread != nullptr &&
               ::WaitForSingleObject(signals.ready, 5000) == WAIT_OBJECT_0;
    }

    [[nodiscard]] bool finish() const noexcept {
        if (signals.release != nullptr) {
            (void)::SetEvent(signals.release);
        }
        return thread == nullptr ||
               ::WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0;
    }
};

#if defined(TESSERA_TEST_WITH_DETOURS)
using LiveHookFn = int(__cdecl*)(int);
volatile int g_live_hook_bias = 10;
LiveHookFn g_live_hook_original = nullptr;

// A volatile global read keeps a real, sufficiently large function body in both
// x86 and x64 Release builds, so Detours has instructions to relocate.
TESSERA_TEST_NOINLINE int __cdecl live_hook_target(int value) {
    return value + g_live_hook_bias;
}

TESSERA_TEST_NOINLINE int __cdecl live_hook_detour(int value) {
    return g_live_hook_original(value) + 100;
}
#endif

class MockHookBackend final : public tessera::HookBackend {
public:
    bool is_available = true;
    int attach_calls = 0;
    int detach_calls = 0;
    bool fail_detach = false;
    bool throw_on_attach = false;
    bool throw_on_detach = false;
    void* trampoline = reinterpret_cast<void*>(&sample_trampoline_function);

    [[nodiscard]] bool available() const noexcept override { return is_available; }

    [[nodiscard]] tessera::Result<tessera::HookToken> attach(
        tessera::Address target,
        void* detour,
        const tessera::HookOptions& options) override {
        ++attach_calls;
        if (throw_on_attach) {
            throw std::bad_alloc{};
        }
        return tessera::HookToken{
            .target = reinterpret_cast<void*>(static_cast<std::uintptr_t>(target.value())),
            .detour = detour,
            .trampoline = trampoline,
            .threads = options.threads,
            .observer = options.observer,
        };
    }

    [[nodiscard]] tessera::Status detach(tessera::HookToken& token) override {
        ++detach_calls;
        if (throw_on_detach) {
            throw std::bad_alloc{};
        }
        if (fail_detach) {
            return tessera::fail(tessera::ErrorCode::Conflict, "MockHookBackend::detach");
        }
        token.trampoline = nullptr;
        return tessera::ok();
    }
};

} // namespace

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

TEST_CASE("Patch apply, restore, expected_original, and PatchTransaction rollback", "[patch]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x500000}, 0x1000, MemoryProtection::ExecuteReadWrite);

    const std::array<std::byte, 4> orig_bytes{
        std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24}};
    backend->poke_bytes(Address{0x500100}, orig_bytes);

    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64);
    ProcessAddress target{proc, Address{0x500100}};

    // Expected original mismatch is rejected before writing
    PatchOptions bad_expect_opt{};
    bad_expect_opt.expected_original = ExpectedBytes{"FF FF FF FF"_sig};
    auto p_bad = Patch::nop(target, 4, bad_expect_opt);
    REQUIRE(p_bad.has_value());
    auto st_bad = p_bad->apply();
    REQUIRE_FALSE(st_bad.has_value());
    REQUIRE(st_bad.error().code == ErrorCode::ValidationFailed);
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});

    // Valid expected_original succeeds and auto_restore restores on scope exit
    {
        PatchOptions good_opt{};
        good_opt.auto_restore = true;
        good_opt.expected_original = ExpectedBytes{"48 89 5C ??"_sig};
        auto p_good = Patch::nop(target, 4, good_opt);
        REQUIRE(p_good.has_value());
        REQUIRE(p_good->apply().has_value());
        REQUIRE(p_good->state() == PatchState::Applied);
        REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x90});
    }
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});

    // PatchTransaction rolls back applied patches when a subsequent patch fails
    backend->poke_bytes(Address{0x500200}, orig_bytes);
    PatchTransaction tx{};
    tx.add(*Patch::nop(ProcessAddress{proc, Address{0x500100}}, 4));
    // Second patch targets unmapped memory -> fails!
    tx.add(*Patch::nop(ProcessAddress{proc, Address{0x999000}}, 4));

    const TransactionReport tx_rep = tx.apply();
    REQUIRE_FALSE(tx_rep.succeeded);
    REQUIRE(tx_rep.applied_count == 1);
    REQUIRE(tx_rep.rolled_back);
    REQUIRE(tx_rep.steps[0].state == PatchState::Restored);
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});

    // Custom Patch::create, idempotent apply/restore, and explicit PatchTransaction::restore_all
    const std::vector<std::byte> custom_bytes{std::byte{0x31}, std::byte{0xC0}};
    auto p_custom = Patch::create(target, custom_bytes);
    REQUIRE(p_custom.has_value());
    REQUIRE(p_custom->apply().has_value());
    REQUIRE(p_custom->apply().has_value()); // idempotent second apply
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x31});
    REQUIRE(p_custom->restore().has_value());
    REQUIRE(p_custom->restore().has_value()); // idempotent second restore
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});
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
        &native_hook_detour,
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
    
    source_info->unwind_code[0].code_offset = 4u;
    source_info->unwind_code[0].operation = kTestUnwindOpAllocSmall | (4u << 4u);
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
    REQUIRE(trampoline_info->unwind_code[0].code_offset == 8u);
    REQUIRE((trampoline_info->unwind_code[0].operation & 0x0Fu) == kTestUnwindOpAllocSmall);
    REQUIRE((trampoline_info->unwind_code[0].operation >> 4u) == 4u);

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
    
    source_info->unwind_code[0].code_offset = 4u;
    source_info->unwind_code[0].operation = kTestUnwindOpAllocSmall | (4u << 4u);
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
                    offsetof(TestUnwindInfo, unwind_code),
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
                    offsetof(TestUnwindInfo, unwind_code),
                &allocation_operation,
                sizeof(allocation_operation));
    const std::uint32_t encoded_allocation = allocation_size;
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    offsetof(TestUnwindInfo, unwind_code) + sizeof(TestUnwindCode),
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
        reinterpret_cast<std::uintptr_t>(trampoline) + kTrampolineEntryPrefixSize + 7u);
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
    code[target_offset + 5u] = std::byte{0xC3};

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
                    offsetof(TestUnwindInfo, unwind_code),
                &save_operation,
                sizeof(save_operation));
    const USHORT scaled_stack_offset = 4u; // 0x20 / sizeof(ULONG64)
    std::memcpy(reinterpret_cast<std::byte*>(source_info) +
                    offsetof(TestUnwindInfo, unwind_code) + sizeof(TestUnwindCode),
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
    const auto entry_stack_pointer =
        reinterpret_cast<std::uintptr_t>(fake_stack.data()) + 16u;
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
        kTrampolineEntryPrefixSize + save_instruction.size());
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

TEST_CASE("Native x64 unwind rejects handler, chained, and non-boundary source metadata",
          "[hook][native][unwind][validation][integration]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    constexpr std::array<std::size_t, 3> target_offsets{64u, 128u, 192u};
    constexpr std::array<std::size_t, 3> unwind_offsets{512u, 528u, 544u};
    std::array<std::array<std::byte, 8>, 3> original{};
    for (std::size_t index = 0; index < target_offsets.size(); ++index) {
        const std::size_t offset = target_offsets[index];
        code[offset + 0u] = std::byte{0x48};
        code[offset + 1u] = std::byte{0x83};
        code[offset + 2u] = std::byte{0xEC};
        code[offset + 3u] = std::byte{0x28}; // sub rsp, 0x28
        code[offset + 4u] = std::byte{0x90};
        std::memcpy(original[index].data(), code + offset, original[index].size());

        auto* unwind_info =
            reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[index]);
        std::memset(unwind_info, 0, 16u);
        unwind_info->version_and_flags = 1u;
        unwind_info->size_of_prolog = 4u;
        unwind_info->count_of_codes = 1u;
        unwind_info->frame_register_and_offset = 0u;
        unwind_info->unwind_code[0].code_offset = 4u;
        unwind_info->unwind_code[0].operation = kTestUnwindOpAllocSmall | (4u << 4u);
    }

    // EHANDLER and CHAININFO must be rejected before reading/using their
    // handler-specific or chained payloads as if they were position-independent.
    reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[0])->version_and_flags =
        static_cast<UCHAR>(1u | (1u << 3u));
    reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[1])->version_and_flags =
        static_cast<UCHAR>(1u | (4u << 3u));
    // A valid v1 record whose CodeOffset lands inside the four-byte SUB
    // instruction, not at its end, must also fail closed.
    reinterpret_cast<TestUnwindInfo*>(code + unwind_offsets[2])->unwind_code[0].code_offset = 2u;

    struct SourceFunctionTableGuard {
        std::array<RUNTIME_FUNCTION, 3> entries{};
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

TEST_CASE("Native inline relocator expands short JMP and conditional branches",
           "[hook][native][relocation]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr,
                       4096,
                       MEM_RESERVE | MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);

    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);
    code[64] = std::byte{0xEB};   // JMP rel8
    code[65] = std::byte{0x7E};   // Target is outside the stolen entry bytes.
    code[192] = std::byte{0xB8};  // mov eax, 42; ret
    code[193] = std::byte{0x2A};
    code[194] = std::byte{0x00};
    code[195] = std::byte{0x00};
    code[196] = std::byte{0x00};
    code[197] = std::byte{0xC3};
    code[256] = std::byte{0x31};  // xor eax, eax (set ZF)
    code[257] = std::byte{0xC0};
    code[258] = std::byte{0x74};  // JE rel8
    code[259] = std::byte{0x7E};  // Target is base + 386.
    code[386] = std::byte{0xB8};  // mov eax, 42; ret
    code[387] = std::byte{0x2A};
    code[388] = std::byte{0x00};
    code[389] = std::byte{0x00};
    code[390] = std::byte{0x00};
    code[391] = std::byte{0xC3};

    // A short jump from the first instruction into the stolen prologue.
    // Its destination must be translated to the corresponding trampoline offset.
    code[768] = std::byte{0xEB};
    code[769] = std::byte{0x02};
    code[770] = std::byte{0x90};
    code[771] = std::byte{0x90};
    code[772] = std::byte{0xB8};
    code[773] = std::byte{0x2A};
    code[774] = std::byte{0x00};
    code[775] = std::byte{0x00};
    code[776] = std::byte{0x00};
    code[777] = std::byte{0xC3};

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto short_jump = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    auto short_conditional = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 256)}, &native_hook_detour, &backend);
    auto internal_branch = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 768)}, &native_hook_detour, &backend);
    REQUIRE(short_jump.has_value());
    REQUIRE(short_conditional.has_value());
    REQUIRE(internal_branch.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(short_jump->install(options).has_value());
    REQUIRE(short_conditional->install(options).has_value());
    REQUIRE(internal_branch->install(options).has_value());

    // The trampoline uses near-branch encodings and remaps internal targets;
    // source prologues are restored byte-for-byte when each hook is removed.
    REQUIRE(short_jump->original() != nullptr);
    REQUIRE(short_conditional->original() != nullptr);
    REQUIRE(internal_branch->original() != nullptr);
    REQUIRE(short_jump->original()(123) == 42);
    REQUIRE(short_conditional->original()(456) == 42);
    REQUIRE(internal_branch->original()(789) == 42);
    REQUIRE(short_jump->remove().has_value());
    REQUIRE(short_conditional->remove().has_value());
    REQUIRE(internal_branch->remove().has_value());
    REQUIRE(code[64] == std::byte{0xEB});
    REQUIRE(code[65] == std::byte{0x7E});
    REQUIRE(code[258] == std::byte{0x74});
    REQUIRE(code[259] == std::byte{0x7E});

}

TEST_CASE("Native inline relocator preserves all LOOP-family branch semantics",
          "[hook][native][relocation][loop]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    const auto write_constant = [code](std::size_t offset, std::uint32_t value) {
        code[offset] = std::byte{0xB8}; // mov eax, imm32
        std::memcpy(code + offset + 1, &value, sizeof(value));
        code[offset + 5] = std::byte{0xC3}; // ret
    };

    // Each counter branch is inside the first five bytes of its entry point.
    // __fastcall puts the counter argument in ECX/RCX on both x86 and x64.
    // LOOPNE: OR AL,1 establishes ZF=0 without changing the counter register.
    code[64] = std::byte{0x0C};
    code[65] = std::byte{0x01};
    code[66] = std::byte{0xE0};
    code[67] = std::byte{0x1C}; // target is +32 from entry

    // LOOPE: XOR EAX,EAX establishes ZF=1 without changing ECX/RCX.
    code[160] = std::byte{0x31};
    code[161] = std::byte{0xC0};
    code[162] = std::byte{0xE1};
    code[163] = std::byte{0x1C};

    // LOOP with count 2 is taken.
    code[256] = std::byte{0xE2};
    code[257] = std::byte{0x1E};

    // JCXZ/JECXZ/JRCXZ takes the branch when the first argument is zero.
    code[352] = std::byte{0xE3};
    code[353] = std::byte{0x1E};

    // LOOP with count 1 is not taken; control must execute the trampoline's
    // fall-through stub and continue at the first untouched source instruction.
    code[448] = std::byte{0xE2};
    code[449] = std::byte{0x1E};
    write_constant(448 + 5, 11);

    // Address-size-prefixed JECXZ retains its 0x67 prefix in the trampoline.
    code[544] = std::byte{0x67};
    code[545] = std::byte{0xE3};
    code[546] = std::byte{0x1D};

    // LOOPNE with a zero result must fall through even though ZF is clear.
    code[736] = std::byte{0x0C};
    code[737] = std::byte{0x01};
    code[738] = std::byte{0xE0};
    code[739] = std::byte{0x1C};

    // LOOPE with a zero result must fall through even though ZF is set.
    code[928] = std::byte{0x31};
    code[929] = std::byte{0xC0};
    code[930] = std::byte{0xE1};
    code[931] = std::byte{0x1C};

    // LOOPE with ZF clear and LOOPNE with ZF set both fall through.
    code[1120] = std::byte{0x0C};
    code[1121] = std::byte{0x01};
    code[1122] = std::byte{0xE1};
    code[1123] = std::byte{0x1C};
    code[1312] = std::byte{0x31};
    code[1313] = std::byte{0xC0};
    code[1314] = std::byte{0xE0};
    code[1315] = std::byte{0x1C};

    // Unprefixed JRCXZ/JECXZ does not branch when the counter is non-zero.
    code[1504] = std::byte{0xE3};
    code[1505] = std::byte{0x1E};

    write_constant(64 + 32, 42);
    write_constant(160 + 32, 42);
    write_constant(256 + 32, 42);
    write_constant(352 + 32, 42);
    write_constant(448 + 32, 42);
    write_constant(544 + 32, 42);
    write_constant(736 + 5, 12);
    write_constant(736 + 32, 42);
    write_constant(928 + 5, 13);
    write_constant(928 + 32, 42);
    write_constant(1120 + 5, 14);
    write_constant(1120 + 32, 42);
    write_constant(1312 + 5, 15);
    write_constant(1312 + 32, 42);
    write_constant(1504 + 5, 16);
    write_constant(1504 + 32, 42);

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    struct LoopCase {
        std::size_t offset;
        std::size_t opcode_offset;
        std::byte opcode;
        std::uintptr_t argument;
        std::uintptr_t expected;
    };
    constexpr std::array<LoopCase, 11> cases{{
        {64, 2, std::byte{0xE0}, 2, 42},
        {160, 2, std::byte{0xE1}, 2, 42},
        {256, 0, std::byte{0xE2}, 2, 42},
        {352, 0, std::byte{0xE3}, 0, 42},
        {448, 0, std::byte{0xE2}, 1, 11},
        {544, 1, std::byte{0xE3}, 0, 42},
        {736, 2, std::byte{0xE0}, 1, 12},
        {928, 2, std::byte{0xE1}, 1, 13},
        {1120, 2, std::byte{0xE1}, 2, 14},
        {1312, 2, std::byte{0xE0}, 2, 15},
        {1504, 0, std::byte{0xE3}, 1, 16},
    }};

    for (const LoopCase& test_case : cases) {
        auto hook = Hook<NativeHookFastFn>::create(
            Address{static_cast<std::uint64_t>(base + test_case.offset)},
            &native_hook_fast_detour,
            &backend);
        REQUIRE(hook.has_value());
        REQUIRE(hook->install(options).has_value());
        REQUIRE(hook->original() != nullptr);
        REQUIRE(hook->original()(test_case.argument) == test_case.expected);
        REQUIRE(hook->remove().has_value());
        REQUIRE(code[test_case.offset + test_case.opcode_offset] == test_case.opcode);
    }
}

TEST_CASE("Native inline relocator executes all sixteen short conditional branch opcodes",
          "[hook][native][relocation][jcc]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // XOR EAX,EAX establishes CF=0, PF=1, ZF=1, SF=0, OF=0.
    // Every short Jcc is followed by MOV EAX,11; RET (not-taken path), while
    // the taken path reaches a helper returning 42 outside the stolen block.
    constexpr std::array<bool, 16> condition_taken{{
        false, true, false, true, true, false, true, false,
        false, true, true, false, false, true, true, false,
    }};

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    for (std::uint8_t condition = 0; condition < 16; ++condition) {
        const std::size_t offset = 64 + static_cast<std::size_t>(condition) * 192;
        code[offset] = std::byte{0x31};
        code[offset + 1] = std::byte{0xC0}; // xor eax,eax
        code[offset + 2] = static_cast<std::byte>(0x70u + condition);
        code[offset + 3] = std::byte{0x3C}; // Target is entry + 64.
        code[offset + 4] = std::byte{0xB8}; // mov eax,11 (fall-through path)
        code[offset + 5] = std::byte{0x0B};
        code[offset + 6] = std::byte{0x00};
        code[offset + 7] = std::byte{0x00};
        code[offset + 8] = std::byte{0x00};
        code[offset + 9] = std::byte{0xC3};
        code[offset + 64] = std::byte{0xB8}; // mov eax,42 (taken path)
        code[offset + 65] = std::byte{0x2A};
        code[offset + 66] = std::byte{0x00};
        code[offset + 67] = std::byte{0x00};
        code[offset + 68] = std::byte{0x00};
        code[offset + 69] = std::byte{0xC3};

        auto hook = Hook<NativeHookFn>::create(
            Address{static_cast<std::uint64_t>(base + offset)},
            &native_hook_detour,
            &backend);
        REQUIRE(hook.has_value());
        REQUIRE(hook->install(options).has_value());

        const auto* trampoline = reinterpret_cast<const std::byte*>(
            reinterpret_cast<std::uintptr_t>(hook->original()));
        REQUIRE(trampoline[0] == std::byte{0xF3});
        REQUIRE(trampoline[1] == std::byte{0x0F});
        REQUIRE(trampoline[2] == std::byte{0x1E});
#if defined(_M_X64) || defined(__x86_64__)
        REQUIRE(trampoline[3] == std::byte{0xFA});
#else
        REQUIRE(trampoline[3] == std::byte{0xFB});
#endif
        REQUIRE(trampoline[6] == std::byte{0x0F});
        REQUIRE(trampoline[7] == static_cast<std::byte>(0x80u + condition));

        const int expected = condition_taken[condition] ? 42 : 11;
        REQUIRE(hook->original()(123) == expected);
        REQUIRE(hook->remove().has_value());
        REQUIRE(code[offset + 2] == static_cast<std::byte>(0x70u + condition));
        REQUIRE(code[offset + 3] == std::byte{0x3C});
        REQUIRE(reinterpret_cast<NativeHookFn>(base + offset)(456) == expected);
    }
}

#if defined(_M_IX86) || defined(__i386__)
TEST_CASE("Native inline x86 relocator rejects operand-size-overridden rel16 CALL",
          "[hook][native][relocation][x86]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // 66 E8 cw is a 16-bit relative CALL in 32-bit mode. Copying it to the
    // trampoline would change its relative destination, while widening it
    // would change the stack return-address width, so reject it fail-closed.
    code[64] = std::byte{0x66};
    code[65] = std::byte{0xE8};
    code[66] = std::byte{0x01};
    code[67] = std::byte{0x00};

    std::array<std::byte, 14> before{};
    std::memcpy(before.data(), code + 64, before.size());

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 64, before.data(), before.size()) == 0);
}
#endif

TEST_CASE("Native inline backend refuses a prologue that cannot fit before a page boundary",
          "[hook][native][boundary]") {
    using namespace tessera;

    constexpr std::size_t page_size = 4096;
    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr,
                       page_size * 2,
                       MEM_RESERVE | MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);

    auto* base_bytes = static_cast<std::byte*>(region.address);
    auto* next_page = base_bytes + page_size;
    DWORD previous_protection = 0;
    REQUIRE(::VirtualProtect(next_page, page_size, PAGE_NOACCESS, &previous_protection));

    auto* target = base_bytes + page_size - 4;
    std::fill(target, target + 4, std::byte{0x90});
    const auto target_address = reinterpret_cast<std::uintptr_t>(target);
    const std::array<std::byte, 4> before{
        target[0], target[1], target[2], target[3]};

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(target_address)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(target, before.data(), before.size()) == 0);
}

TEST_CASE("Native inline relocator repairs rel32 CALL, JMP, and near Jcc operands",
          "[hook][native][relocation][rel32]") {
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
    const auto write_rel32 = [code](std::size_t field,
                                    std::size_t next_instruction,
                                    std::size_t destination) {
        const auto displacement = static_cast<std::int32_t>(
            static_cast<std::int64_t>(destination) -
            static_cast<std::int64_t>(next_instruction));
        std::memcpy(code + field, &displacement, sizeof(displacement));
    };

    // CALL rel32 followed by ADD EAX,35 and RET. The helper returns 7.
    code[768] = std::byte{0xE8};
    write_rel32(769, 773, 1024);
    code[773] = std::byte{0x83};
    code[774] = std::byte{0xC0};
    code[775] = std::byte{0x23};
    code[776] = std::byte{0xC3};
    write_constant(1024, 7);

    // 0F 84 rel32 (JE) taken after XOR; the target helper returns 42.
    code[1280] = std::byte{0x31};
    code[1281] = std::byte{0xC0};
    code[1282] = std::byte{0x0F};
    code[1283] = std::byte{0x84};
    write_rel32(1284, 1288, 1536);
    code[1288] = std::byte{0xB8};
    code[1289] = std::byte{0x0B};
    code[1290] = std::byte{0x00};
    code[1291] = std::byte{0x00};
    code[1292] = std::byte{0x00};
    code[1293] = std::byte{0xC3};
    write_constant(1536, 42);

    // E9 rel32 follows a NOP so this is a genuine in-prologue branch,
    // not an existing entry thunk (which the backend intentionally rejects).
    code[1792] = std::byte{0x90};
    code[1793] = std::byte{0xE9};
    write_rel32(1794, 1798, 1824);
    write_constant(1824, 42);

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    auto call_hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 768)}, &native_hook_detour, &backend);
    auto conditional_hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 1280)}, &native_hook_detour, &backend);
    auto jump_hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 1792)}, &native_hook_detour, &backend);
    REQUIRE(call_hook.has_value());
    REQUIRE(conditional_hook.has_value());
    REQUIRE(jump_hook.has_value());

    REQUIRE(call_hook->install(options).has_value());
    REQUIRE(call_hook->original()(1) == 42);
    REQUIRE(call_hook->remove().has_value());

    REQUIRE(conditional_hook->install(options).has_value());
    REQUIRE(conditional_hook->original()(2) == 42);
    REQUIRE(conditional_hook->remove().has_value());

    REQUIRE(jump_hook->install(options).has_value());
    REQUIRE(jump_hook->original()(3) == 42);
    REQUIRE(jump_hook->remove().has_value());

    REQUIRE(code[768] == std::byte{0xE8});
    REQUIRE(code[1282] == std::byte{0x0F});
    REQUIRE(code[1283] == std::byte{0x84});
    REQUIRE(code[1793] == std::byte{0xE9});
}

TEST_CASE("Native inline relocator rejects CALL-next PC materialization without patching",
          "[hook][native][relocation][call-pop]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // CALL $+5 / POP reg is a position-independent-code idiom that reads the
    // caller's original instruction pointer. Relocating the CALL would push
    // the trampoline IP instead, so this prologue must fail closed.
    code[64] = std::byte{0xE8};
    std::memset(code + 65, 0, 4);
    code[69] = std::byte{0x5B}; // pop ebx/rbx
    code[70] = std::byte{0x90};

    std::array<std::byte, 14> before{};
    std::memcpy(before.data(), code + 64, before.size());

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status.has_value());
    REQUIRE(status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 64, before.data(), before.size()) == 0);
}

TEST_CASE("Native inline relocator survives a deterministic malformed-prologue corpus without changing rejected code",
          "[hook][native][fuzz][safety]") {
    using namespace tessera;

    constexpr std::size_t region_size = 64 * 1024;
    constexpr std::size_t sample_stride = 128;
    constexpr std::size_t sample_count = 256;
    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr,
                       region_size,
                       MEM_RESERVE | MEM_COMMIT,
                       PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);

    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, region_size);

    // Fixed-seed xorshift32 corpus: reproducible across x86/x64 and CI runs.
    std::uint32_t random_state = 0xC0FFEE42u;
    const auto next_random = [&random_state]() noexcept {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 17;
        random_state ^= random_state << 5;
        return random_state;
    };

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    std::size_t installed_count = 0;
    std::size_t rejected_count = 0;
    for (std::size_t sample = 0; sample < sample_count; ++sample) {
        const std::size_t offset = 64 + sample * sample_stride;
        for (std::size_t i = 0; i < 96; ++i) {
            code[offset + i] = static_cast<std::byte>(next_random() & 0xFFu);
        }
        if (sample == 0) {
            code[offset] = std::byte{0xB8}; // mov eax,42
            const std::uint32_t known_result = 42;
            std::memcpy(code + offset + 1, &known_result, sizeof(known_result));
            code[offset + 5] = std::byte{0xC3}; // ret
        }

        // Keep a snapshot larger than the maximum patch window. Rejected
        // prologues must be byte-for-byte untouched.
        std::array<std::byte, 96> before{};
        std::memcpy(before.data(), code + offset, before.size());

        auto hook = Hook<NativeHookFn>::create(
            Address{static_cast<std::uint64_t>(base + offset)},
            &native_hook_detour,
            &backend);
        REQUIRE(hook.has_value());

        const auto status = hook->install(options);
        if (status) {
            ++installed_count;
            REQUIRE(hook->installed());
            if (sample == 0) {
                REQUIRE(hook->original()(0) == 42);
            }
            REQUIRE(hook->remove().has_value());
            REQUIRE_FALSE(hook->installed());
        } else {
            ++rejected_count;
        }

        REQUIRE(std::memcmp(code + offset, before.data(), before.size()) == 0);
    }

    REQUIRE(installed_count + rejected_count == sample_count);
    // Random data should exercise both the fail-closed path and occasional
    // valid instruction streams, rather than accidentally testing only one.
    REQUIRE(installed_count > 0);
    REQUIRE(rejected_count > 0);
}

TEST_CASE("Native inline relocator rejects branches into instruction middles and RIP-relative reads into the stolen block",
          "[hook][native][relocation][rejection]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // JMP lands on the second byte of the following MOV immediate.
    code[64] = std::byte{0xEB};
    code[65] = std::byte{0x01};
    code[66] = std::byte{0xB8};
    code[67] = std::byte{0x2A};
    code[68] = std::byte{0x00};
    code[69] = std::byte{0x00};
    code[70] = std::byte{0x00};
    const std::array<std::byte, 14> branch_before = [&] {
        std::array<std::byte, 14> bytes{};
        std::memcpy(bytes.data(), code + 64, bytes.size());
        return bytes;
    }();

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;
    auto middle_branch = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 64)}, &native_hook_detour, &backend);
    REQUIRE(middle_branch.has_value());
    const auto middle_status = middle_branch->install(options);
    REQUIRE_FALSE(middle_status.has_value());
    REQUIRE(middle_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 64, branch_before.data(), branch_before.size()) == 0);

    // Conservatively reject prefixed short JMP/Jcc forms whose prefix semantics
    // are not represented by the normalized expanded encodings.
    code[512] = std::byte{0x66};
    code[513] = std::byte{0xEB};
    code[514] = std::byte{0x7E};
    code[768] = std::byte{0x66};
    code[769] = std::byte{0x74};
    code[770] = std::byte{0x7E};
    const std::array<std::byte, 14> prefixed_jump_before = [&] {
        std::array<std::byte, 14> bytes{};
        std::memcpy(bytes.data(), code + 512, bytes.size());
        return bytes;
    }();
    const std::array<std::byte, 14> prefixed_jcc_before = [&] {
        std::array<std::byte, 14> bytes{};
        std::memcpy(bytes.data(), code + 768, bytes.size());
        return bytes;
    }();

    auto prefixed_jump = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 512)}, &native_hook_detour, &backend);
    auto prefixed_jcc = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 768)}, &native_hook_detour, &backend);
    REQUIRE(prefixed_jump.has_value());
    REQUIRE(prefixed_jcc.has_value());
    const auto prefixed_jump_status = prefixed_jump->install(options);
    const auto prefixed_jcc_status = prefixed_jcc->install(options);
    REQUIRE_FALSE(prefixed_jump_status.has_value());
    REQUIRE_FALSE(prefixed_jcc_status.has_value());
    REQUIRE(prefixed_jump_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(prefixed_jcc_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 512, prefixed_jump_before.data(), prefixed_jump_before.size()) == 0);
    REQUIRE(std::memcmp(code + 768, prefixed_jcc_before.data(), prefixed_jcc_before.size()) == 0);

    // CALL $+5 materializes the original program counter on the stack.
    // Relocating it would expose the trampoline PC, so it must fail closed.
    code[1024] = std::byte{0xE8};
    const std::int32_t call_next_displacement = 0;
    std::memcpy(code + 1025, &call_next_displacement, sizeof(call_next_displacement));
    const std::array<std::byte, 14> call_next_before = [&] {
        std::array<std::byte, 14> bytes{};
        std::memcpy(bytes.data(), code + 1024, bytes.size());
        return bytes;
    }();
    auto call_next = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 1024)}, &native_hook_detour, &backend);
    REQUIRE(call_next.has_value());
    const auto call_next_status = call_next->install(options);
    REQUIRE_FALSE(call_next_status.has_value());
    REQUIRE(call_next_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 1024, call_next_before.data(), call_next_before.size()) == 0);

#if defined(_M_X64) || defined(__x86_64__)
    // MOV RAX,[RIP+disp32] points back into bytes that the entry patch would overwrite.
    code[256] = std::byte{0x48};
    code[257] = std::byte{0x8B};
    code[258] = std::byte{0x05};
    const std::int32_t rip_displacement = -2; // next RIP is +7; target is +5 inside the stolen block
    std::memcpy(code + 259, &rip_displacement, sizeof(rip_displacement));
    const std::array<std::byte, 14> rip_before = [&] {
        std::array<std::byte, 14> bytes{};
        std::memcpy(bytes.data(), code + 256, bytes.size());
        return bytes;
    }();

    auto rip_into_prologue = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 256)}, &native_hook_detour, &backend);
    REQUIRE(rip_into_prologue.has_value());
    const auto rip_status = rip_into_prologue->install(options);
    REQUIRE_FALSE(rip_status.has_value());
    REQUIRE(rip_status.error().code == ErrorCode::UnsupportedInstruction);
    REQUIRE(std::memcmp(code + 256, rip_before.data(), rip_before.size()) == 0);
#endif
}

TEST_CASE("Native inline relocator decodes VEX and EVEX instructions without executing them",
          "[hook][native][relocation][avx]") {
    using namespace tessera;

    ExecutableRegionGuard region{
        ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
    REQUIRE(region.address != nullptr);
    auto* code = static_cast<std::byte*>(region.address);
    std::memset(code, 0x90, 4096);

    // VZEROUPPER (VEX) followed by VADDPS ZMM0,ZMM0,ZMM0 (EVEX).
    // This test verifies decoding/copying only: the instructions are never run,
    // so the test does not require AVX or AVX-512 CPU support.
    constexpr std::array<std::byte, 9> instructions{
        std::byte{0xC5}, std::byte{0xF8}, std::byte{0x77},
        std::byte{0x62}, std::byte{0xF1}, std::byte{0x7C},
        std::byte{0x48}, std::byte{0x58}, std::byte{0xC0}};
    std::memcpy(code + 2048, instructions.data(), instructions.size());

    const auto base = reinterpret_cast<std::uintptr_t>(region.address);
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<NativeHookFn>::create(
        Address{static_cast<std::uint64_t>(base + 2048)}, &native_hook_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    REQUIRE(hook->original() != nullptr);
    const auto trampoline_code = reinterpret_cast<const std::byte*>(
        reinterpret_cast<std::uintptr_t>(hook->original()) + 4);
    REQUIRE(std::memcmp(trampoline_code, instructions.data(), instructions.size()) == 0);
    REQUIRE(hook->remove().has_value());
    REQUIRE(std::memcmp(code + 2048, instructions.data(), instructions.size()) == 0);
}

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
    REQUIRE(first_trampoline[9] == std::byte{0xE9});
    REQUIRE(reinterpret_cast<const std::byte*>(reinterpret_cast<std::uintptr_t>(second->original()))[9] == std::byte{0xE9});
    REQUIRE(reinterpret_cast<const std::byte*>(reinterpret_cast<std::uintptr_t>(third->original()))[9] == std::byte{0xE9});

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

TEST_CASE("Native patch transaction reports initial protection failure without writing",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {false};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::InitialProtectionFailure);
    REQUIRE(ops.copy_calls == 0);
    REQUIRE(target == original);
    REQUIRE(native_error == 5678);
    REQUIRE((ops.events == std::vector<char>{'p'}));
}

TEST_CASE("Native patch transaction rolls back after instruction-cache flush failure",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, true};
    ops.flush_results = {false, true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FlushRolledBack);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(native_error == 9012);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'f', 'C', 'F', 'P'}));
}

TEST_CASE("Native patch transaction rolls back after protection restoration failure",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, false, true};
    ops.flush_results = {true, true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::ProtectionRolledBack);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(ops.protect_index == 3);
    REQUIRE(native_error == 5678);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'F', 'p', 'C', 'F', 'P'}));
}

TEST_CASE("Native patch transaction identifies an unrecoverable rollback",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true};
    ops.flush_results = {false, false, false};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FatalRollback);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(ops.current_protection == 0x40UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'f', 'C', 'f', 'f'}));
}


TEST_CASE("Native patch transaction identifies unrecoverable protection restoration",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, false, false, false};
    ops.flush_results = {true, true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FatalRollback);
    REQUIRE(target == original);
    REQUIRE(ops.protect_index == 4);
    REQUIRE(ops.current_protection == 0x40UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'F', 'p', 'C', 'F', 'p', 'p'}));
}


TEST_CASE("Native patch transaction writes and restores protection on success",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, true};
    ops.flush_results = {true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long previous_protection = 0;
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, &previous_protection, native_error);

    REQUIRE(result == PatchWriteOutcome::Success);
    REQUIRE(target == replacement);
    REQUIRE(previous_protection == 0x20UL);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE(ops.copy_calls == 1);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'F', 'P'}));
}


TEST_CASE("Native patch transaction retries rollback flush and protection restoration",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, false, true};
    ops.protect_errors = {0UL, 5201UL, 5202UL};
    ops.flush_results = {false, false, true};
    ops.flush_errors = {9101UL, 9102UL, 9103UL};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FlushRolledBack);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(ops.protect_index == 3);
    REQUIRE(ops.flush_index == 3);
    REQUIRE(native_error == 9101UL);
    REQUIRE(ops.error == 5201UL);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'f', 'C', 'f', 'F', 'p', 'P'}));
}
