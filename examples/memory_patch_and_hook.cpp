#include "tessera/tessera.hpp"

#include <array>
#include <cstdint>
#include <iostream>

namespace {

int __cdecl calculate_damage(int base_dmg) {
    return base_dmg * 2;
}

int __cdecl detour_calculate_damage(int base_dmg) {
    return base_dmg * 10;
}

} // namespace

int main() {
    using namespace tessera;
    using namespace tessera::literals;

    std::cout << "=== Tessera Example 02: Memory Reader/Writer, Patch, Transaction & Hook ===\n\n";

    const Process proc = Process::current();
    MemoryReader reader{proc};
    MemoryWriter writer{proc};

    // 1. Direct typed read & write in local memory
    std::uint32_t armor_value = 150;
    const Address armor_addr = Address::from_ptr(&armor_value);
    std::cout << "[Memory]  Initial armor: " << reader.read<std::uint32_t>(armor_addr).value_or(0)
              << "\n";

    (void)writer.write_value<std::uint32_t>(armor_addr, 275);
    std::cout << "[Memory]  Updated armor: " << reader.read<std::uint32_t>(armor_addr).value_or(0)
              << "\n";

    // 2. Scoped Patch with expected_original validation and automatic RAII restore
    alignas(16) std::array<std::byte, 6> instruction_buf{
        std::byte{0x89}, std::byte{0x48}, std::byte{0x08}, // mov [rax+8], ecx
        std::byte{0x90}, std::byte{0x90}, std::byte{0xC3}  // nop; nop; ret
    };
    const ProcessAddress code_target{proc, Address::from_ptr(instruction_buf.data())};

    {
        PatchOptions opts{};
        opts.auto_restore = true;
        opts.expected_original = ExpectedBytes{"89 48 08"_sig};

        auto nop_patch = Patch::nop(code_target, 3, opts);
        if (nop_patch && nop_patch->apply().has_value()) {
            std::cout << "[Patch]   Applied 3-byte NOP patch (first byte = 0x" << std::hex
                      << static_cast<unsigned>(instruction_buf[0]) << std::dec << ")\n";
        }
    }
    std::cout << "[Patch]   Scope exited -> auto_restore restored first byte = 0x" << std::hex
              << static_cast<unsigned>(instruction_buf[0]) << std::dec << "\n";

    // 3. Multi-patch atomic PatchTransaction
    PatchTransaction tx{};
    const std::vector<std::byte> custom_op{std::byte{0x31}, std::byte{0xC0}}; // xor eax, eax
    tx.add(*Patch::create(code_target, custom_op));
    const TransactionReport tx_rep = tx.apply();
    std::cout << "[Tx]      PatchTransaction applied (" << tx_rep.applied_count
              << " patch), restoring all...\n";
    (void)tx.restore_all();

    // 4. Typed Hook<Fn> wrapper
    using DamageFn = int(__cdecl*)(int);
    auto dmg_hook = Hook<DamageFn>::create(&calculate_damage, &detour_calculate_damage);
    if (dmg_hook.has_value()) {
        std::cout << "[Hook]    Created Hook<DamageFn>; direct call result = " << (*dmg_hook)(25)
                  << " (Detours backend available: "
                  << (default_hook_backend().available() ? "yes" : "no") << ")\n";
    }

    return 0;
}
