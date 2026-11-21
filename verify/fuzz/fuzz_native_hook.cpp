#include "tessera/hook/hook.hpp"

#include "fuzz_corpus_runner.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace {

constexpr std::size_t kCodeRegionSize = 4096;
constexpr std::size_t kTargetOffset = 64;
constexpr std::size_t kFuzzRegionSize = 96;

// The standalone CI smoke mode uses this counter to ensure that at least the
// known-good seed reached and completed a real attach/detach lifecycle.
std::uint64_t g_successful_lifecycles = 0;
std::uint64_t g_total_inputs = 0;

extern "C" __declspec(noinline) void tessera_fuzz_detour() noexcept {
    // The fuzz harness validates decoding and patch lifecycle; it never calls
    // either the generated trampoline or the fuzz-provided instruction bytes.
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        std::abort();
    }
    ++g_total_inputs;

    void* allocation = ::VirtualAlloc(
        nullptr, kCodeRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation == nullptr) {
        // Infrastructure failures must never be counted as successful fuzz
        // inputs; doing so could silently skip most of a campaign.
        std::abort();
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
        std::abort();
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
        ++g_successful_lifecycles;
    }

    if (!::VirtualFree(allocation, 0, MEM_RELEASE)) {
        // A leaked executable page can invalidate later iterations.
        std::abort();
    }
    return 0;
}

#if !defined(TESSERA_LIBFUZZER)
int main(int argc, char** argv) {
    const bool corpus_mode = argc > 1;
    if (corpus_mode) {
        const int replay_status = tessera::fuzz::run_corpus(argc, argv, &LLVMFuzzerTestOneInput);
        if (replay_status != 0) {
            return replay_status;
        }
    }
    const auto stress_started = std::chrono::steady_clock::now();

    // Keep a known-good seed first so standalone CI smoke mode proves that the
    // native backend can still complete at least one real lifecycle.
    constexpr std::array<std::uint8_t, 6> simple_prologue{
        0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3
    };
    const std::uint64_t lifecycle_count_before_baseline = g_successful_lifecycles;
    (void)LLVMFuzzerTestOneInput(simple_prologue.data(), simple_prologue.size());
    if (g_successful_lifecycles != lifecycle_count_before_baseline + 1u) {
        std::abort();
    }

    // Small, deterministic seeds focus the native relocator's less common
    // paths. The bytes are decoded and copied but are never executed.
    constexpr std::array<std::uint8_t, 6> short_jump{
        0xEB, 0x02, 0x90, 0x90, 0x90, 0xC3
    };
    constexpr std::array<std::uint8_t, 6> short_conditional{
        0x74, 0x02, 0x90, 0x90, 0x90, 0xC3
    };
    constexpr std::array<std::uint8_t, 6> loop_branch{
        0xE2, 0x02, 0x90, 0x90, 0x90, 0xC3
    };
    constexpr std::array<std::uint8_t, 6> near_jump{
        0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3
    };
    constexpr std::array<std::uint8_t, 7> near_conditional{
        0x0F, 0x85, 0x00, 0x00, 0x00, 0x00, 0xC3
    };
    constexpr std::array<std::uint8_t, 6> call_next{
        0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3
    };
    constexpr std::array<std::uint8_t, 5> terminal_padding{
        0xC3, 0xCC, 0xCC, 0xCC, 0xCC
    };
    constexpr std::array<std::uint8_t, 5> vex_instruction{
        0xC5, 0xF8, 0x77, 0x90, 0x90
    };
    constexpr std::array<std::uint8_t, 7> evex_instruction{
        0x62, 0xF1, 0x7C, 0x48, 0x58, 0xC0, 0x90
    };

    (void)LLVMFuzzerTestOneInput(short_jump.data(), short_jump.size());
    (void)LLVMFuzzerTestOneInput(short_conditional.data(), short_conditional.size());
    (void)LLVMFuzzerTestOneInput(loop_branch.data(), loop_branch.size());
    (void)LLVMFuzzerTestOneInput(near_jump.data(), near_jump.size());
    (void)LLVMFuzzerTestOneInput(near_conditional.data(), near_conditional.size());
    (void)LLVMFuzzerTestOneInput(call_next.data(), call_next.size());
    (void)LLVMFuzzerTestOneInput(terminal_padding.data(), terminal_padding.size());
    (void)LLVMFuzzerTestOneInput(vex_instruction.data(), vex_instruction.size());
    (void)LLVMFuzzerTestOneInput(evex_instruction.data(), evex_instruction.size());

    // Add a reproducible malformed/novel-input corpus to every normal CI run.
    // A fixed xorshift seed makes failures deterministic and easy to reproduce.
    std::uint32_t random_state = 0xC0FFEE42u;
    const auto next_random = [&random_state]() noexcept {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 17;
        random_state ^= random_state << 5;
        return random_state;
    };

    constexpr std::size_t kRandomSampleCount = 65536;
    std::array<std::uint8_t, kFuzzRegionSize> random_input{};
    if (!corpus_mode) {
        for (std::size_t sample = 0; sample < kRandomSampleCount; ++sample) {
            const std::size_t length =
                1u + (static_cast<std::size_t>(next_random()) % random_input.size());
            for (std::size_t index = 0; index < length; ++index) {
                random_input[index] = static_cast<std::uint8_t>(next_random() & 0xFFu);
            }
            (void)LLVMFuzzerTestOneInput(random_input.data(), length);
        }
    }

    const auto elapsed = std::chrono::steady_clock::now() - stress_started;
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    const auto inputs_per_second = elapsed_ms > 0
        ? (g_total_inputs * 1000u) / static_cast<std::uint64_t>(elapsed_ms)
        : 0u;
    std::printf(
        "native-hook-stress-summary: inputs=%llu successful_lifecycles=%llu elapsed_ms=%lld inputs_per_second=%llu\n",
        static_cast<unsigned long long>(g_total_inputs),
        static_cast<unsigned long long>(g_successful_lifecycles),
        static_cast<long long>(elapsed_ms),
        static_cast<unsigned long long>(inputs_per_second));

    return 0;
}
#endif // !defined(TESSERA_LIBFUZZER)
