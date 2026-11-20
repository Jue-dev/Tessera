#include "patch_hook_test_support.hpp"

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

