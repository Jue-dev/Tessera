#if !defined(_M_IX86) && !defined(__i386__)
#error "This file contains 32-bit Windows native-hook tests only."
#endif

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <utility>

#include <Windows.h>

#include "hook/backends/x86_instruction_decoder.hpp"
#include "FakeMemoryBackend.hpp"
#include "tessera/hook/hook.hpp"
#include "tessera/memory/memory_writer.hpp"

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

CdeclFn g_short_branch_original = nullptr;

int __cdecl short_branch_detour(int value) {
    return g_short_branch_original != nullptr ? g_short_branch_original(value) + 100 : -1;
}

CdeclFn g_multi_original_a = nullptr;
CdeclFn g_multi_original_b = nullptr;
volatile LONG g_x86_thread_stop = 0;

int __cdecl multi_detour_a(int value) {
    return g_multi_original_a != nullptr ? g_multi_original_a(value) + 100 : -1;
}

int __cdecl multi_detour_b(int value) {
    return g_multi_original_b != nullptr ? g_multi_original_b(value) + 100 : -1;
}

class PartialWriteOnceBackend final : public tessera::IMemoryBackend {
public:
    explicit PartialWriteOnceBackend(std::shared_ptr<tessera::testing::FakeMemoryBackend> inner)
        : inner_(std::move(inner)) {}

    [[nodiscard]] tessera::Result<std::size_t> read(
        tessera::Address address, std::span<std::byte> buffer) const override {
        return inner_->read(address, buffer);
    }

    [[nodiscard]] tessera::Result<std::size_t> write(
        tessera::Address address, std::span<const std::byte> data) const override {
        if (partial_write_pending_ && data.size() > 1) {
            partial_write_pending_ = false;
            return inner_->write(address, data.first(data.size() / 2));
        }
        return inner_->write(address, data);
    }

    [[nodiscard]] tessera::Result<tessera::MemoryRegionInfo> query(
        tessera::Address address) const override {
        return inner_->query(address);
    }

    [[nodiscard]] tessera::Result<tessera::MemoryProtection> protect(
        tessera::Address address,
        std::uint64_t size,
        tessera::MemoryProtection protection) const override {
        return inner_->protect(address, size, protection);
    }

    [[nodiscard]] tessera::Status flush_instruction_cache(
        tessera::AddressRange range) const override {
        return inner_->flush_instruction_cache(range);
    }

private:
    std::shared_ptr<tessera::testing::FakeMemoryBackend> inner_;
    mutable bool partial_write_pending_ = true;
};

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

TEST_CASE("Native x86 relocator expands short JMP and Jcc while preserving trampoline behavior",
          "[hook][native][x86][relocation]") {
    using namespace tessera;

    const auto run_case = [](const auto& target_code) {
        ExecutableRegion region{};
        REQUIRE(region.address != nullptr);
        auto* code = region.bytes();
        std::memset(code, 0x90, 4096);
        constexpr std::size_t target_offset = 64;
        std::memcpy(code + target_offset, target_code.data(), target_code.size());
        REQUIRE(region.protect_read_execute());

        HookBackend& backend = native_inline_hook_backend();
        auto hook = Hook<CdeclFn>::create(
            reinterpret_cast<CdeclFn>(code + target_offset), &short_branch_detour, &backend);
        REQUIRE(hook.has_value());
        HookOptions options{};
        options.threads = ThreadPolicy::None;
        const auto install_status = hook->install(options);
        REQUIRE(install_status.has_value());
        g_short_branch_original = hook->original();
        REQUIRE(reinterpret_cast<CdeclFn>(code + target_offset)(5) == 142);
        REQUIRE(hook->original()(5) == 42);
        REQUIRE(hook->remove().has_value());
        g_short_branch_original = nullptr;
        REQUIRE(reinterpret_cast<CdeclFn>(code + target_offset)(5) == 42);
    };

    // JMP +2 skips two NOPs and lands on the MOV at the next instruction boundary.
    const std::array<std::byte, 10> short_jmp{
        std::byte{0xEB}, std::byte{0x02}, std::byte{0x90}, std::byte{0x90},
        std::byte{0xB8}, std::byte{0x2A}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0xC3}};
    run_case(short_jmp);

    // JZ +2 targets the MOV after two NOPs; XOR makes the taken path deterministic.
    const std::array<std::byte, 12> short_jcc{
        std::byte{0x31}, std::byte{0xC0}, std::byte{0x74}, std::byte{0x02},
        std::byte{0x90}, std::byte{0x90}, std::byte{0xB8}, std::byte{0x2A},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xC3}};
    run_case(short_jcc);
}


TEST_CASE("Native x86 relocator rejects branches into the middle of a displaced instruction",
          "[hook][native][x86][relocation][rejection]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);

    constexpr std::size_t target_offset = 64;
    // The short Jcc targets byte 67, inside the immediate of the MOV at byte 66.
    const std::array<std::byte, 8> target_code{
        std::byte{0x74}, std::byte{0x01},
        std::byte{0xB8}, std::byte{0x2A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xC3}};
    std::memcpy(code + target_offset, target_code.data(), target_code.size());
    REQUIRE(region.protect_read_execute());

    std::array<std::byte, 8> before{};
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

TEST_CASE("Native x86 decoder accepts short and near relative boundary encodings",
          "[hook][native][x86][relocation][boundaries]") {
    using namespace tessera::detail::x86;

    const auto check_relative = [](std::span<const std::byte> bytes,
                                   std::size_t expected_size,
                                   std::uint8_t expected_opcode,
                                   std::uint8_t expected_opcode2 = 0) {
        DecodedInstruction decoded{};
        REQUIRE(decode_instruction(bytes.data(), bytes.size(), Mode::x86, decoded));
        REQUIRE(decoded.has_relative_operand);
        REQUIRE(decoded.relative_size == expected_size);
        REQUIRE(decoded.opcode == expected_opcode);
        if (expected_opcode2 != 0) {
            REQUIRE(decoded.opcode2 == expected_opcode2);
        }
    };

    const std::array<std::byte, 2> short_jmp_min{std::byte{0xEB}, std::byte{0x80}};
    const std::array<std::byte, 2> short_jcc_max{std::byte{0x75}, std::byte{0x7F}};
    const std::array<std::byte, 5> near_jmp_min{
        std::byte{0xE9}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x80}};
    const std::array<std::byte, 5> near_call_max{
        std::byte{0xE8}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0x7F}};
    const std::array<std::byte, 6> near_jcc_max{
        std::byte{0x0F}, std::byte{0x85}, std::byte{0xFF},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0x7F}};

    check_relative(short_jmp_min, 1, 0xEB);
    check_relative(short_jcc_max, 1, 0x75);
    check_relative(near_jmp_min, 4, 0xE9);
    check_relative(near_call_max, 4, 0xE8);
    check_relative(near_jcc_max, 4, 0x0F, 0x85);
}

TEST_CASE("Native x86 relocator preserves near JMP, CALL, and Jcc trampoline behavior",
          "[hook][native][x86][relocation]") {
    using namespace tessera;

    const auto run_case = [](std::span<const std::byte> target_code) {
        ExecutableRegion region{};
        REQUIRE(region.address != nullptr);
        auto* code = region.bytes();
        std::memset(code, 0x90, 4096);
        constexpr std::size_t target_offset = 64;
        std::memcpy(code + target_offset, target_code.data(), target_code.size());
        REQUIRE(region.protect_read_execute());

        HookBackend& backend = native_inline_hook_backend();
        auto hook = Hook<CdeclFn>::create(
            reinterpret_cast<CdeclFn>(code + target_offset), &short_branch_detour, &backend);
        REQUIRE(hook.has_value());
        HookOptions options{};
        options.threads = ThreadPolicy::None;
        const auto install_status = hook->install(options);
        REQUIRE(install_status.has_value());
        g_short_branch_original = hook->original();
        REQUIRE(reinterpret_cast<CdeclFn>(code + target_offset)(5) == 142);
        REQUIRE(hook->original()(5) == 42);
        REQUIRE(hook->remove().has_value());
        g_short_branch_original = nullptr;
        REQUIRE(reinterpret_cast<CdeclFn>(code + target_offset)(5) == 42);
    };

    // CALL rel8 is not an x86 encoding; near CALL targets a separate RET stub.
    const std::array<std::byte, 12> near_call{
        std::byte{0xE8}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xB8}, std::byte{0x2A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xC3}, std::byte{0xC3}};
    run_case(near_call);

    const std::array<std::byte, 11> near_jmp{
        std::byte{0xE9}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xB8}, std::byte{0x2A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xC3}};
    run_case(near_jmp);

    const std::array<std::byte, 16> near_jcc{
        std::byte{0x31}, std::byte{0xC0},
        std::byte{0x0F}, std::byte{0x84}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x90}, std::byte{0x90},
        std::byte{0xB8}, std::byte{0x2A}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0xC3}};
    run_case(near_jcc);
}

TEST_CASE("Native x86 hook rejects short terminal prologues without modifying target bytes",
          "[hook][native][x86][rejection]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);
    constexpr std::size_t target_offset = 64;
    const std::array<std::byte, 3> short_function{
        std::byte{0xC3}, std::byte{0x0F}, std::byte{0x0B}}; // RET followed by UD2, not safe padding.
    std::memcpy(code + target_offset, short_function.data(), short_function.size());
    REQUIRE(region.protect_read_execute());

    std::array<std::byte, 8> before{};
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

TEST_CASE("Native x86 hooks support multiple installations and both uninstall orders",
          "[hook][native][x86][lifecycle]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);
    constexpr std::size_t first_offset = 64;
    constexpr std::size_t second_offset = 128;
    const std::array<std::byte, 6> first_code{
        std::byte{0xB8}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0xC3}};
    const std::array<std::byte, 6> second_code{
        std::byte{0xB8}, std::byte{0x02}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0xC3}};
    std::memcpy(code + first_offset, first_code.data(), first_code.size());
    std::memcpy(code + second_offset, second_code.data(), second_code.size());
    REQUIRE(region.protect_read_execute());

    HookBackend& backend = native_inline_hook_backend();
    HookOptions options{};
    options.threads = ThreadPolicy::None;

    auto first = Hook<CdeclFn>::create(
        reinterpret_cast<CdeclFn>(code + first_offset), &multi_detour_a, &backend);
    auto second = Hook<CdeclFn>::create(
        reinterpret_cast<CdeclFn>(code + second_offset), &multi_detour_b, &backend);
    REQUIRE(first);
    REQUIRE(second);
    REQUIRE(first->install(options));
    g_multi_original_a = first->original();
    REQUIRE(second->install(options));
    g_multi_original_b = second->original();

    REQUIRE(reinterpret_cast<CdeclFn>(code + first_offset)(0) == 101);
    REQUIRE(reinterpret_cast<CdeclFn>(code + second_offset)(0) == 102);

    // Deliberately remove the first hook while the second remains installed.
    REQUIRE(first->remove());
    g_multi_original_a = nullptr;
    REQUIRE(reinterpret_cast<CdeclFn>(code + first_offset)(0) == 1);
    REQUIRE(reinterpret_cast<CdeclFn>(code + second_offset)(0) == 102);
    REQUIRE(second->remove());
    g_multi_original_b = nullptr;

    // Reinstall both and also verify the normal LIFO order.
    auto first_lifo = Hook<CdeclFn>::create(
        reinterpret_cast<CdeclFn>(code + first_offset), &multi_detour_a, &backend);
    auto second_lifo = Hook<CdeclFn>::create(
        reinterpret_cast<CdeclFn>(code + second_offset), &multi_detour_b, &backend);
    REQUIRE(first_lifo);
    REQUIRE(second_lifo);
    REQUIRE(first_lifo->install(options));
    g_multi_original_a = first_lifo->original();
    REQUIRE(second_lifo->install(options));
    g_multi_original_b = second_lifo->original();
    REQUIRE(second_lifo->remove());
    g_multi_original_b = nullptr;
    REQUIRE(first_lifo->remove());
    g_multi_original_a = nullptr;
    REQUIRE(reinterpret_cast<CdeclFn>(code + first_offset)(0) == 1);
    REQUIRE(reinterpret_cast<CdeclFn>(code + second_offset)(0) == 2);
}

TEST_CASE("x86 memory writes roll back a partial transfer before returning failure",
          "[hook][native][x86][rollback]") {
    using namespace tessera;

    constexpr Address kBase{0x10000};
    auto storage = std::make_shared<testing::FakeMemoryBackend>();
    storage->map_region(kBase, 4096, MemoryProtection::ReadWrite);
    const std::array<std::byte, 8> original{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    const std::array<std::byte, 8> replacement{
        std::byte{8}, std::byte{7}, std::byte{6}, std::byte{5},
        std::byte{4}, std::byte{3}, std::byte{2}, std::byte{1}};
    storage->poke_bytes(kBase, original);

    auto backend = std::make_shared<PartialWriteOnceBackend>(storage);
    const ProcessInfo info{
        .pid = ProcessId{4242},
        .architecture = Architecture::X86,
        .pointer_size = 4,
        .is_local = false,
        .granted_access = ProcessAccess::ReadWriteQuery,
        .max_application_address = 0xFFEFFFFFULL,
    };
    auto process = Process::from_backend(info, backend);
    REQUIRE(process);

    MemoryWriter writer{std::move(*process)};
    auto report = writer.write_with_report(kBase, replacement);
    REQUIRE(report);
    REQUIRE(report->write_error.has_value());
    REQUIRE(report->write_error->code == ErrorCode::PartialTransfer);
    REQUIRE(report->rolled_back);
    REQUIRE_FALSE(report->rollback_error.has_value());

    for (std::size_t index = 0; index < original.size(); ++index) {
        REQUIRE(storage->peek_byte(Address{kBase.value() + index}) == original[index]);
    }
}

TEST_CASE("Native x86 strict thread policy rejects an EIP inside the displaced prologue",
          "[hook][native][x86][threading]") {
    using namespace tessera;

    ExecutableRegion region{};
    REQUIRE(region.address != nullptr);
    auto* code = region.bytes();
    std::memset(code, 0x90, 4096);
    constexpr std::size_t target_offset = 64;
    auto* target = code + target_offset;

    const std::uint32_t stop_address = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(&g_x86_thread_stop));
    const std::array<std::byte, 13> thread_code{
        std::byte{0x90},                         // target entry
        std::byte{0x83}, std::byte{0x3D},         // cmp dword ptr [absolute], 0
        static_cast<std::byte>(stop_address & 0xFFu),
        static_cast<std::byte>((stop_address >> 8u) & 0xFFu),
        static_cast<std::byte>((stop_address >> 16u) & 0xFFu),
        static_cast<std::byte>((stop_address >> 24u) & 0xFFu),
        std::byte{0x00},                         // imm8
        std::byte{0x74}, std::byte{0xF7},         // jz back to the CMP at offset 1
        std::byte{0xC2}, std::byte{0x04}, std::byte{0x00}}; // ret 4 (thread start ABI)
    std::memcpy(target, thread_code.data(), thread_code.size());
    REQUIRE(region.protect_read_execute());
    ::InterlockedExchange(&g_x86_thread_stop, 0);

    DWORD thread_id = 0;
    const auto start_routine = reinterpret_cast<LPTHREAD_START_ROUTINE>(target + 1);
    HANDLE thread = ::CreateThread(nullptr, 0, start_routine, nullptr, CREATE_SUSPENDED, &thread_id);
    REQUIRE(thread != nullptr);

    // Let the OS thread bootstrap reach the test stub, then hold it and pin EIP
    // to the first byte of the displaced CMP instruction.
    struct ScopedTestThread {
        HANDLE handle = nullptr;
        ~ScopedTestThread() {
            if (handle == nullptr) {
                return;
            }
            ::InterlockedExchange(&g_x86_thread_stop, 1);
            DWORD previous_count = ::ResumeThread(handle);
            while (previous_count != static_cast<DWORD>(-1) && previous_count > 1) {
                previous_count = ::ResumeThread(handle);
            }
            (void)::WaitForSingleObject(handle, 5000);
            (void)::CloseHandle(handle);
        }
    } thread_guard{thread};

    REQUIRE(::ResumeThread(thread) != static_cast<DWORD>(-1));
    bool pinned_inside_patch = false;
    bool manually_suspended = false;
    for (std::size_t attempt = 0; attempt < 1000 && !pinned_inside_patch; ++attempt) {
        if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
            break;
        }
        manually_suspended = true;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if (::GetThreadContext(thread, &context) != FALSE) {
            const DWORD instruction_pointer = static_cast<DWORD>(context.Eip);
            const DWORD stub_begin =
                static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(target + 1));
            const DWORD stub_end =
                static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(target + 11));
            if (instruction_pointer >= stub_begin && instruction_pointer < stub_end) {
                context.Eip = stub_begin;
                pinned_inside_patch = ::SetThreadContext(thread, &context) != FALSE;
            }
        }
        if (!pinned_inside_patch) {
            (void)::ResumeThread(thread);
            manually_suspended = false;
            ::Sleep(1);
        }
    }
    REQUIRE(pinned_inside_patch);
    REQUIRE(manually_suspended);

    std::array<std::byte, 13> before{};
    std::memcpy(before.data(), target, before.size());
    HookBackend& backend = native_inline_hook_backend();
    auto hook = Hook<CdeclFn>::create(
        reinterpret_cast<CdeclFn>(target), &unused_detour, &backend);
    REQUIRE(hook);

    HookOptions options{};
    options.threads = ThreadPolicy::SuspendOthersStrict;
    const auto status = hook->install(options);
    REQUIRE_FALSE(status);
    REQUIRE(status.error().code == ErrorCode::Conflict);
    REQUIRE(std::memcmp(target, before.data(), before.size()) == 0);

}

