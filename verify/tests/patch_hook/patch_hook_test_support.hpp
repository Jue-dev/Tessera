#pragma once

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

[[maybe_unused]] int __cdecl sample_target_function(int x) {
    return x + 10;
}

[[maybe_unused]] int __cdecl sample_detour_function(int x) {
    return x + 100;
}

[[maybe_unused]] int __cdecl sample_trampoline_function(int x) {
    return x + 10;
}

[[maybe_unused]] int __cdecl sample_alternate_trampoline_function(int x) {
    return x + 20;
}

std::atomic<bool> g_callable_lease_entered{false};
std::atomic<bool> g_callable_lease_release{false};

[[maybe_unused]] int __cdecl blocking_trampoline_function(int value) {
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

[[maybe_unused]] int __cdecl blocking_lease_detour(int value) {
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
};

constexpr std::size_t kTestUnwindCodeOffset = sizeof(TestUnwindInfo);
constexpr std::size_t kTestTrampolineEntryPrefixSize = 4u;
constexpr UCHAR kTestUnwindOpPushNonVol = 0u; // UWOP_PUSH_NONVOL
constexpr UCHAR kTestUnwindOpAllocSmall = 2u;
[[maybe_unused]] void set_test_unwind_code(
    TestUnwindInfo* info,
    std::size_t slot,
    TestUnwindCode code) noexcept {
    auto* const destination =
        reinterpret_cast<std::byte*>(info) +
        kTestUnwindCodeOffset + slot * sizeof(TestUnwindCode);
    std::memcpy(destination, &code, sizeof(code));
}

[[maybe_unused]] [[nodiscard]] TestUnwindCode get_test_unwind_code(
    const TestUnwindInfo* info,
    std::size_t slot) noexcept {
    TestUnwindCode code{};
    const auto* const source =
        reinterpret_cast<const std::byte*>(info) +
        kTestUnwindCodeOffset + slot * sizeof(TestUnwindCode);
    std::memcpy(&code, source, sizeof(code));
    return code;
}

static_assert(sizeof(TestUnwindInfo) == 4u);
static_assert(sizeof(TestUnwindCode) == 2u);
[[maybe_unused]] DWORD __cdecl invoke_breakpoint_trampoline(NativeHookFn trampoline) noexcept {
    __try {
        (void)trampoline(0);
    } __except (GetExceptionCode() == EXCEPTION_BREAKPOINT
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        return ::GetExceptionCode();
    }
    return ERROR_SUCCESS;
}
#endif
tessera::Hook<NativeHookFn>* g_recursive_lease_hook = nullptr;
std::atomic<bool> g_remove_from_lease_rejected{false};
std::atomic<bool> g_release_from_lease_rejected{false};

[[maybe_unused]] int __cdecl remove_from_callable_lease_trampoline(int value) {
    const auto result = g_recursive_lease_hook->remove();
    g_remove_from_lease_rejected.store(
        !result.has_value() && result.error().code == tessera::ErrorCode::Conflict,
        std::memory_order_release);
    const NativeHookFn released = g_recursive_lease_hook->release();
    g_release_from_lease_rejected.store(released == nullptr, std::memory_order_release);
    return value + 7;
}

[[maybe_unused]] int __cdecl recursive_trampoline_function(int value) {
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
[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl native_hook_target(int value) {
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

[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl native_hook_detour(int value) {
    return g_native_hook_original(value) + 100;
}

[[maybe_unused]] TESSERA_TEST_NOINLINE std::uintptr_t __fastcall native_hook_fast_detour(std::uintptr_t value) {
    return value + 500;
}

[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl native_hook_detour_1000(int value) {
    return value + 1000;
}

[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl native_hook_detour_2000(int value) {
    return value + 2000;
}

[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl native_hook_detour_3000(int value) {
    return value + 3000;
}

struct WaitingWorkerSignals {
    HANDLE ready = nullptr;
    HANDLE release = nullptr;
};

[[maybe_unused]] DWORD WINAPI native_hook_waiting_worker(void* context) {
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
[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl live_hook_target(int value) {
    return value + g_live_hook_bias;
}

[[maybe_unused]] TESSERA_TEST_NOINLINE int __cdecl live_hook_detour(int value) {
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

