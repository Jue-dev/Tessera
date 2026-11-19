#include <atomic>

#include <Windows.h>

namespace {

using NativeHookFn = int(__cdecl*)(int);

std::atomic<NativeHookFn> g_original{nullptr};
std::atomic<HANDLE> g_entered_event{nullptr};
std::atomic<HANDLE> g_release_event{nullptr};
std::atomic<LONG> g_active_calls{0};

} // namespace

extern "C" __declspec(dllexport) void __cdecl tessera_fixture_configure(
    NativeHookFn original,
    HANDLE entered_event,
    HANDLE release_event) noexcept {
    g_original.store(original, std::memory_order_release);
    g_entered_event.store(entered_event, std::memory_order_release);
    g_release_event.store(release_event, std::memory_order_release);
}

extern "C" __declspec(dllexport) LONG __cdecl
tessera_fixture_active_calls() noexcept {
    return g_active_calls.load(std::memory_order_acquire);
}

extern "C" __declspec(dllexport) int __cdecl
tessera_fixture_detour(int value) noexcept {
    g_active_calls.fetch_add(1, std::memory_order_acq_rel);

    const HANDLE entered =
        g_entered_event.load(std::memory_order_acquire);
    if (entered != nullptr) {
        (void)::SetEvent(entered);
    }

    const HANDLE release =
        g_release_event.load(std::memory_order_acquire);
    if (release != nullptr &&
        ::WaitForSingleObject(release, 15000) != WAIT_OBJECT_0) {
        g_active_calls.fetch_sub(1, std::memory_order_acq_rel);
        return -1;
    }

    const NativeHookFn original =
        g_original.load(std::memory_order_acquire);
    const int result = original != nullptr ? original(value) + 1000 : -1;
    g_active_calls.fetch_sub(1, std::memory_order_acq_rel);
    return result;
}
