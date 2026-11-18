#include "tessera/tessera.hpp"

#include <cstdint>
#include <iostream>
#include <optional>
#include <span>

int main() {
    using namespace tessera;
    using namespace tessera::literals;

    std::cout << "=== Tessera Example 01: Process, PE Analysis, Pattern Scan & Resolver ===\n\n";

    const Process proc = Process::current();
    std::cout << "[Process] PID: " << proc.pid().value()
              << " | Arch: " << (proc.pointer_size() == 8 ? "x64" : "x86") << "\n";

    // 1. Module enumeration & PE header inspection (Sections, Exports, Imports, .pdata, CodeView)
    if (auto main_mod = ModuleCatalog::main_module(proc)) {
        auto name_utf8 = encoding::utf16_to_utf8(main_mod->name());
        std::cout << "[Module]  Main: " << (name_utf8 ? *name_utf8 : "<invalid-utf8>") << " @ "
                  << hex::format_u64(main_mod->base().value()) << " (" << main_mod->size()
                  << " bytes)\n";

        if (auto pe = main_mod->image()) {
            std::cout << "[PE]      Sections: " << pe->sections().size()
                      << " | Imports: " << pe->imports().size()
                      << " | .pdata Functions: " << pe->exception_functions().size() << "\n";

            for (const auto& sec : pe->sections()) {
                std::cout << "          - Section " << sec.name << " RVA="
                          << hex::format_u64(sec.rva.value()) << " Size=" << sec.virtual_size
                          << "\n";
            }

            if (auto cv = pe->code_view()) {
                std::cout << "[PDB]     Path: " << cv->pdb_path << " (Age: " << cv->age << ")\n";
            }
        }
    }

    // 2. Inspect kernel32.dll exports via PeImage
    if (auto k32 = ModuleCatalog::find(proc, u"kernel32.dll")) {
        if (auto k32_pe = k32->image()) {
            if (auto exp = k32_pe->find_export("GetCurrentProcessId")) {
                std::cout << "[Export]  kernel32!GetCurrentProcessId @ "
                          << hex::format_u64(exp->address.value()) << "\n";
            }
        }
    }

    // 3. Compile-time pattern literal (_sig) + nibble wildcards + fluent AddressCursor & Pipe syntax
    alignas(16) const std::uint8_t sample_code[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
        0xE8, 0x05, 0x00, 0x00, 0x00, // call +5 (target at offset 15)
        0x90, 0x90, 0x90, 0x90, 0x90, // nop padding
        0xCC                          // target byte (int3)
    };

    constexpr auto sig = "48 89 5C 24 ? E8"_sig;
    const auto bytes = std::as_bytes(std::span{sample_code});
    std::optional<std::size_t> offset;
    sig.search(bytes, bytes.size(), [&](std::size_t idx) {
        offset = idx;
        return false;
    });

    if (offset.has_value()) {
        const auto match_addr = Address::from_ptr(sample_code + *offset);
        const ProcessAddress paddr{proc, match_addr};

        // Style A: Fluent cursor chaining
        auto target_a = paddr.cursor().offset(5).follow_branch().address();
        // Style B: Pipe (|) operator chaining
        auto target_b =
            Result<ProcessAddress>{paddr} | resolve::offset(5) | resolve::follow_branch;

        if (target_a.has_value() && target_b.has_value()) {
            std::cout << "[Cursor]  Resolved E8 call target: "
                      << hex::format_u64(target_a->value())
                      << " (Pipe match: " << (*target_a == target_b->address() ? "yes" : "no")
                      << ")\n";
        }
    }

    return 0;
}
