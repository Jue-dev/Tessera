#include "tessera/hook/hook.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace {

constexpr std::size_t kCodeRegionSize = 4096;
constexpr std::size_t kTargetOffset = 64;
constexpr std::size_t kFuzzRegionSize = 96;

extern "C" __declspec(noinline) void tessera_fuzz_detour() noexcept {
    // The fuzz harness validates decoding and patch lifecycle; it never calls
    // either the generated trampoline or the fuzz-provided instruction bytes.
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        return 0;
    }

    void* allocation = ::VirtualAlloc(
        nullptr, kCodeRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation == nullptr) {
        return 0;
    }

    auto* const code = static_cast<std::byte*>(allocation);
    std::memset(code, 0x90, kCodeRegionSize);
    const std::size_t copied = (std::min)(size, kFuzzRegionSize);
    if (copied != 0) {
        std::memcpy(code + kTargetOffset, data, copied);
    }

    std::array<std::byte, kFuzzRegionSize> original{};
    std::memcpy(original.data(), code + kTargetOffset, original.size());

    DWORD previous_protection = 0;
    if (!::VirtualProtect(allocation, kCodeRegionSize, PAGE_EXECUTE_READ,
                          &previous_protection)) {
        (void)::VirtualFree(allocation, 0, MEM_RELEASE);
        return 0;
    }

    tessera::HookOptions options{};
    options.threads = tessera::ThreadPolicy::None;
    auto attached = tessera::native_inline_hook_backend().attach(
        tessera::Address{static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(code + kTargetOffset))},
        reinterpret_cast<void*>(&tessera_fuzz_detour),
        options);

    if (!attached) {
        // A rejected instruction stream must be failure-atomic.
        if (std::memcmp(code + kTargetOffset, original.data(), original.size()) != 0) {
            std::abort();
        }
    } else {
        auto token = std::move(*attached);
        const auto detached = tessera::native_inline_hook_backend().detach(token);
        if (!detached || token.backend_data != nullptr) {
            // Continuing would leave a registry entry or a live patch pointing
            // into memory that this harness is about to release.
            std::abort();
        }
        if (std::memcmp(code + kTargetOffset, original.data(), original.size()) != 0) {
            std::abort();
        }
    }

    (void)::VirtualFree(allocation, 0, MEM_RELEASE);
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main() {
    // A valid, simple prologue exercises the successful attach/detach path.
    constexpr std::array<std::uint8_t, 6> sample{
        0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3
    };
    return LLVMFuzzerTestOneInput(sample.data(), sample.size());
}
#endif // !defined(TESSERA_LIBFUZZER)
