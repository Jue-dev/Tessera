#if !defined(_M_IX86) && !defined(__i386__)
#error "This file contains 32-bit Windows native-hook tests only."
#endif

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <Windows.h>

#include "hook/backends/x86_instruction_decoder.hpp"
#include "tessera/hook/hook.hpp"

namespace {

using StdcallFn = int(__stdcall*)(int, int);
using FastcallFn = int(__fastcall*)(int, int);
using ThiscallFn = int(__thiscall*)(void*, int);
using CdeclFn = int(__cdecl*)(int);

StdcallFn g_stdcall_original = nullptr;
FastcallFn g_fastcall_original = nullptr;
ThiscallFn g_thiscall_original = nullptr;

int __stdcall stdcall_detour(int lhs, int rhs) {
    return g_stdcall_original != nullptr ? g_stdcall_original(lhs, rhs) + 100 : -1;
}

int __fastcall fastcall_detour(int lhs, int rhs) {
    return g_fastcall_original != nullptr ? g_fastcall_original(lhs, rhs) + 100 : -1;
}

// A fastcall detour is ABI-compatible with a thiscall target on x86:
// ECX carries the object pointer, EDX is an ignored second register, and
// remaining arguments are stack-passed and callee-cleaned.
int __fastcall thiscall_detour(void* object, void* /*edx*/, int value) {
    return g_thiscall_original != nullptr ? g_thiscall_original(object, value) + 100 : -1;
}

int __cdecl unused_detour(int value) {
    return value + 100;
}

struct ExecutableRegion final {
    void* address = ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    ExecutableRegion() = default;
    ExecutableRegion(const ExecutableRegion&) = delete;
    ExecutableRegion& operator=(const ExecutableRegion&) = delete;

    ~ExecutableRegion() noexcept {
        if (address != nullptr) {
            (void)::VirtualFree(address, 0, MEM_RELEASE);
        }
    }

    [[nodiscard]] std::byte* bytes() const noexcept {
        return static_cast<std::byte*>(address);
    }

    [[nodiscard]] bool protect_read_execute() noexcept {
        DWORD previous = 0;
        return address != nullptr &&
               ::VirtualProtect(address, 4096, PAGE_EXECUTE_READ, &previous) != FALSE;
    }
};

template <typename To, typename From>
To copy_function_pointer(From source) noexcept {
    static_assert(sizeof(To) == sizeof(From));
    To destination{};
    std::memcpy(&destination, &source, sizeof(destination));
    return destination;
}

template <typename Fn, typename... Args>
int call_and_check_stack(Fn function, Args... args) {
    DWORD before = 0;
    DWORD after = 0;
    __asm mov before, esp
    const int result = function(args...);
    __asm mov after, esp
    REQUIRE(before == after);
    return result;
}

} // namespace

TEST_CASE("Native x86 hooks preserve stdcall stack cleanup and trampoline behavior",
          "[hook][native][x86][abi]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64;
    // mov eax,[esp+4]; add eax,[esp+8]; ret 8
    const std::array<std::byte, 11> target_code{
        std::byte{0x8B}, std::byte{0x44}, std::byte{0x24}, std::byte{0x04},
        std::byte{0x03}, std::byte{0x44}, std::byte{0x24}, std::byte{0x08},
        std::byte{0xC2}, std::byte{0x08}, std::byte{0x00}};
    std::memcpy(code + target_offset, target_code.data(), target_code.size());
    REQUIRE(region.protect_read_execute());

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<StdcallFn>::create(
        reinterpret_cast<StdcallFn>(code + target_offset), &stdcall_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    g_stdcall_original = hook->original();

    REQUIRE(call_and_check_stack(reinterpret_cast<StdcallFn>(code + target_offset), 5, 7) == 112);
    REQUIRE(call_and_check_stack(hook->original(), 5, 7) == 12);
    REQUIRE(hook->remove().has_value());
    g_stdcall_original = nullptr;
    REQUIRE(call_and_check_stack(reinterpret_cast<StdcallFn>(code + target_offset), 5, 7) == 12);
}

TEST_CASE("Native x86 hooks preserve fastcall register arguments",
          "[hook][native][x86][abi]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64;
    // mov eax,ecx; add eax,edx; ret
    // Exactly five bytes are needed for the x86 entry JMP patch.
    const std::array<std::byte, 5> target_code{
        std::byte{0x8B}, std::byte{0xC1}, std::byte{0x03},
        std::byte{0xC2}, std::byte{0xC3}};
    std::memcpy(code + target_offset, target_code.data(), target_code.size());
    REQUIRE(region.protect_read_execute());

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<FastcallFn>::create(
        reinterpret_cast<FastcallFn>(code + target_offset), &fastcall_detour, &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    g_fastcall_original = hook->original();

    REQUIRE(call_and_check_stack(reinterpret_cast<FastcallFn>(code + target_offset), 5, 7) == 112);
    REQUIRE(call_and_check_stack(hook->original(), 5, 7) == 12);
    REQUIRE(hook->remove().has_value());
    g_fastcall_original = nullptr;
    REQUIRE(call_and_check_stack(reinterpret_cast<FastcallFn>(code + target_offset), 5, 7) == 12);
}

TEST_CASE("Native x86 hooks preserve thiscall ECX and stack argument behavior",
          "[hook][native][x86][abi]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64;
    // mov eax,ecx; add eax,[esp+4]; ret 4
    const std::array<std::byte, 9> target_code{
        std::byte{0x8B}, std::byte{0xC1}, std::byte{0x03}, std::byte{0x44},
        std::byte{0x24}, std::byte{0x04}, std::byte{0xC2}, std::byte{0x04},
        std::byte{0x00}};
    std::memcpy(code + target_offset, target_code.data(), target_code.size());
    REQUIRE(region.protect_read_execute());

    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<ThiscallFn>::create(
        reinterpret_cast<ThiscallFn>(code + target_offset),
        copy_function_pointer<ThiscallFn>(&thiscall_detour),
        &backend);
    REQUIRE(hook.has_value());

    HookOptions options{};
    options.threads = ThreadPolicy::None;
    REQUIRE(hook->install(options).has_value());
    g_thiscall_original = hook->original();

    void* object = reinterpret_cast<void*>(static_cast<std::uintptr_t>(5));
    REQUIRE(call_and_check_stack(reinterpret_cast<ThiscallFn>(code + target_offset), object, 7) == 112);
    REQUIRE(call_and_check_stack(hook->original(), object, 7) == 12);
    REQUIRE(hook->remove().has_value());
    g_thiscall_original = nullptr;
    REQUIRE(call_and_check_stack(reinterpret_cast<ThiscallFn>(code + target_offset), object, 7) == 12);
}

TEST_CASE("Native x86 relocator rejects rel16 JMP, Jcc, and XBEGIN without patching",
          "[hook][native][x86][relocation][rejection]") {
    using namespace tessera;
    using namespace tessera::detail::x86;

    const std::array<std::array<std::uint8_t, 5>, 3> encodings{{
        {{0x66, 0xE9, 0x01, 0x00, 0x90}}, // JMP rel16 + NOP
        {{0x66, 0x0F, 0x84, 0x01, 0x00}}, // Jcc rel16
        {{0x66, 0xC7, 0xF8, 0x01, 0x00}}, // XBEGIN rel16
    }};

    for (std::size_t index = 0; index < encodings.size(); ++index) {
        DecodedInstruction decoded{};
        const auto* encoded = reinterpret_cast<const std::byte*>(encodings[index].data());
        REQUIRE(decode_instruction(encoded, encodings[index].size(), Mode::x86, decoded));
        REQUIRE(decoded.has_relative_operand);
        REQUIRE(decoded.relative_size == 2);

        ExecutableRegion region{};
        REQUIRE(region.address != nullptr);
        auto* code = region.bytes();
        std::memset(code, 0x90, 4096);
        constexpr std::size_t target_offset = 64;
        std::memcpy(code + target_offset, encodings[index].data(), encodings[index].size());
        REQUIRE(region.protect_read_execute());

        std::array<std::byte, 14> before{};
        std::memcpy(before.data(), code + target_offset, before.size());
        HookBackend& backend = native_inline_hook_backend();
        auto hook = Hook<CdeclFn>::create(
            reinterpret_cast<CdeclFn>(code + target_offset), &unused_detour, &backend);
        REQUIRE(hook.has_value());

        HookOptions options{};
        options.threads = ThreadPolicy::None;
        const auto status = hook->install(options);
        REQUIRE_FALSE(status.has_value());
        REQUIRE(status.error().code == ErrorCode::UnsupportedInstruction);
        REQUIRE(std::memcmp(code + target_offset, before.data(), before.size()) == 0);
    }
}
