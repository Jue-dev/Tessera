#include "tessera/tessera.hpp"

#include <array>
#include <cstdint>
#include <iostream>

int main() {
    using namespace tessera;
    using namespace tessera::rtti;

    std::cout << "=== Tessera Example 04: Blind Binary Discovery (Strings, Functions & Non-Virtual Struct Reconstruction) ===\n\n";

    const Process proc = Process::current();
    auto main_mod = ModuleCatalog::main_module(proc);
    if (!main_mod.has_value()) {
        return 1;
    }

    // 1. Scan all TypeDescriptors (including non-virtual .?AU structs and .?AW4 enums)
    auto rtti_cat = RttiCatalog::discover_all(proc, main_mod->range());
    if (auto all_tds = BinaryExplorer::scan_all_type_descriptors(
            proc, main_mod->range(), rtti_cat ? &(*rtti_cat) : nullptr)) {
        std::cout << "[Discovery] Total TypeDescriptors in binary (virtual + non-virtual): "
                  << all_tds->size() << "\n";
    }

    // 2. Scan ASCII/UTF-16 string literals in the binary
    if (auto strings = BinaryExplorer::scan_strings(proc, main_mod->range(), 12, false)) {
        std::cout << "[Discovery] Sampled string literals found: " << strings->size() << "\n";
    }

    // 3. Reconstruct a non-virtual C++ struct layout directly from x64 machine instructions!
    //    Suppose we found a function operating on `rcx` (the `this` pointer of an unknown struct):
    //      8B 41 08          mov eax, [rcx + 0x08]        -> Int32 read at +0x08
    //      89 51 0C          mov [rcx + 0x0C], edx        -> Int32 write at +0x0C
    //      F3 0F 10 41 10    movss xmm0, [rcx + 0x10]     -> Float32 read at +0x10
    //      C6 41 14 01       mov byte ptr [rcx + 0x14], 1 -> UInt8 write at +0x14
    //      48 8B 41 18       mov rax, [rcx + 0x18]        -> Pointer/UInt64 read at +0x18
    //      C3                ret
    alignas(16) const std::array<std::uint8_t, 20> sample_fn_bytes{
        0x8B, 0x41, 0x08,
        0x89, 0x51, 0x0C,
        0xF3, 0x0F, 0x10, 0x41, 0x10,
        0xC6, 0x41, 0x14, 0x01,
        0x48, 0x8B, 0x41, 0x18,
        0xC3,
    };

    const AddressRange fn_range{Address::from_ptr(sample_fn_bytes.data()), sample_fn_bytes.size()};
    if (auto recon = BinaryExplorer::reconstruct_struct(proc, fn_range, "Inferred::UnknownActor")) {
        std::cout << "\n[Reconstruct] Inferred non-virtual struct '" << recon->name_hint
                  << "' (estimated size: " << recon->estimated_size << " bytes):\n";
        for (const auto& f : recon->fields) {
            std::cout << "              +0x" << std::hex << f.offset << std::dec << " ("
                      << f.size << " bytes, read=" << f.is_read
                      << ", write=" << f.is_written << ")\n";
        }
    }

    // 4. ReClass-style Memory Dissection on a live memory block
    struct SampleMemoryBlock {
        const char* label = "HeroActor_01";
        std::int32_t level = 45;
        float move_speed = 5.25f;
    } sample_block;

    if (auto slots = BinaryExplorer::dissect_memory(
            proc,
            main_mod->range(),
            Address::from_ptr(&sample_block),
            sizeof(sample_block),
            rtti_cat ? &(*rtti_cat) : nullptr)) {
        std::cout << "\n[Dissect]     Dissected " << slots->size() << " memory slots:\n";
        for (const auto& s : *slots) {
            std::cout << "              +0x" << std::hex << s.offset << std::dec;
            if (s.kind == MemorySlotKind::PointerToAsciiString) {
                std::cout << " -> PointerToAsciiString: \"" << s.string_preview << "\"\n";
            } else if (s.kind == MemorySlotKind::Integer32) {
                std::cout << " -> Integer32: " << s.i32_value << "\n";
            } else if (s.kind == MemorySlotKind::Float32) {
                std::cout << " -> Float32: " << s.f32_value << "\n";
            } else {
                std::cout << " -> Raw value: " << hex::format_u64(s.raw_u64) << "\n";
            }
        }
    }

    return 0;
}
