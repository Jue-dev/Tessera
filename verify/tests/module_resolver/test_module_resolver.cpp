#include <catch2/catch_test_macros.hpp>

#include <array>
#include <random>
#include <vector>

#include "FakeMemoryBackend.hpp"
#include "tessera/module/module.hpp"
#include "tessera/module/pe_image.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/resolver/resolver.hpp"
#include "tessera/scanner/xref.hpp"

#if !defined(TESSERA_PORTABLE_VALIDATION)
TEST_CASE("ModuleCatalog and PeImage parsing on current process", "[module][pe]") {
    using namespace tessera;

    Process self = Process::current();
    auto main_mod = ModuleCatalog::main_module(self);
    REQUIRE(main_mod.has_value());
    REQUIRE_FALSE(main_mod->name().empty());
    REQUIRE_FALSE(main_mod->range().empty());

    auto main_pe = main_mod->image();
    REQUIRE(main_pe.has_value());
    REQUIRE_FALSE(main_pe->imports().empty());
    if (self.pointer_size() == 8) {
        REQUIRE_FALSE(main_pe->exception_functions().empty());
    }

    // Empty name to ModuleCatalog::find is rejected (no silent main module fallback)
    REQUIRE_FALSE(ModuleCatalog::find(self, u"").has_value());

    // Find kernel32.dll case-insensitively
    auto k32 = ModuleCatalog::find(self, u"KeRnEl32.dLl");
    REQUIRE(k32.has_value());

    auto k32_pe = k32->image();
    REQUIRE(k32_pe.has_value());
    REQUIRE_FALSE(k32_pe->sections().empty());
    REQUIRE(k32_pe->find_section(".text").has_value());

    // Resolve exported function via PeImage without GetProcAddress
    auto exp = k32_pe->find_export("GetCurrentProcessId");
    REQUIRE(exp.has_value());
    REQUIRE_FALSE(exp->rva.is_zero());
    REQUIRE_FALSE(exp->address.is_null());

    // Corrupt PE bytes and random fuzz mutations are safely rejected without crashing
    const std::array<std::byte, 64> bad_pe{std::byte{0x4D}, std::byte{0x5A}};
    REQUIRE_FALSE(PeImage::from_raw_bytes(bad_pe).has_value());

    std::mt19937 rng{0x7E55E4Au};
    for (std::size_t len = 0; len <= 512; len += 16) {
        std::vector<std::byte> fuzz_buf(len);
        for (auto& b : fuzz_buf) {
            b = static_cast<std::byte>(rng() & 0xFFu);
        }
        if (len >= 2) {
            fuzz_buf[0] = std::byte{'M'};
            fuzz_buf[1] = std::byte{'Z'};
        }
        auto parsed = PeImage::from_raw_bytes(fuzz_buf);
        if (parsed.has_value()) {
            (void)parsed->sections();
            (void)parsed->exports();
            (void)parsed->imports();
            (void)parsed->exception_functions();
            (void)parsed->code_view();
        }
    }
}

#endif // !TESSERA_PORTABLE_VALIDATION

TEST_CASE("PE32 HIGHLOW relocations support x86 relocation-aware xrefs", "[pe][relocations][xref][x86]") {
    using namespace tessera;
    using namespace tessera::testing;

    std::vector<std::byte> bytes(0x600);
    auto put16 = [&](std::size_t offset, std::uint16_t value) {
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    };
    auto put32 = [&](std::size_t offset, std::uint32_t value) {
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    };

    put16(0, 0x5A4D);
    put32(0x3C, 0x80);
    put32(0x80, 0x00004550);
    put16(0x84, 0x014C);
    put16(0x86, 2);
    put16(0x94, 0x00E0);

    constexpr std::size_t opt = 0x98;
    put16(opt, 0x010B);
    put32(opt + 16, 0x1000);
    put32(opt + 28, 0x00400000);
    put32(opt + 32, 0x1000);
    put32(opt + 36, 0x200);
    put32(opt + 56, 0x3000);
    put32(opt + 60, 0x200);
    put32(opt + 92, 16);
    put32(opt + 96 + 5 * 8, 0x2000);
    put32(opt + 96 + 5 * 8 + 4, 12);

    constexpr std::size_t text = 0x178;
    bytes[text] = std::byte{'.'};
    bytes[text + 1] = std::byte{'t'};
    bytes[text + 2] = std::byte{'e'};
    bytes[text + 3] = std::byte{'x'};
    bytes[text + 4] = std::byte{'t'};
    put32(text + 8, 0x1000);
    put32(text + 12, 0x1000);
    put32(text + 16, 0x200);
    put32(text + 20, 0x200);
    put32(text + 36, 0x60000020);

    constexpr std::size_t reloc = text + 40;
    bytes[reloc] = std::byte{'.'};
    bytes[reloc + 1] = std::byte{'r'};
    bytes[reloc + 2] = std::byte{'e'};
    bytes[reloc + 3] = std::byte{'l'};
    bytes[reloc + 4] = std::byte{'o'};
    bytes[reloc + 5] = std::byte{'c'};
    put32(reloc + 8, 0x100);
    put32(reloc + 12, 0x2000);
    put32(reloc + 16, 0x200);
    put32(reloc + 20, 0x400);
    put32(reloc + 36, 0x42000040);

    put32(0x210, 0x00401234);
    put32(0x400, 0x1000);
    put32(0x404, 12);
    put16(0x408, 0x3010);
    put16(0x40A, 0x0000);

    auto image = PeImage::from_raw_bytes(bytes);
    REQUIRE(image.has_value());
    REQUIRE(image->kind() == PeKind::Pe32);
    REQUIRE(image->relocations().size() == 1);
    REQUIRE(image->relocations()[0].type == 3u);
    REQUIRE(image->relocations()[0].location == Rva{0x1010});

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x500000}, 0x3000, MemoryProtection::ExecuteReadWrite);
    backend->poke_bytes(Address{0x500000}, std::span<const std::byte>{bytes}.first(0x200));
    backend->poke_bytes(Address{0x501000}, std::span<const std::byte>{bytes}.subspan(0x200, 0x200));
    backend->poke_bytes(Address{0x502000}, std::span<const std::byte>{bytes}.subspan(0x400, 0x200));
    backend->poke_value<std::uint32_t>(Address{0x501010}, 0x501234u);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X86);
    auto mapped = PeImage::from_memory(process, Address{0x500000});
    REQUIRE(mapped.has_value());
    auto refs = xref::find_relocated_pointer_refs(
        process, Address{0x500000}, *mapped, Address{0x501234});
    REQUIRE(refs.has_value());
    REQUIRE(refs->size() == 1);
    REQUIRE(refs->front() == Address{0x501010});
}

TEST_CASE("Resolver fluent AddressCursor and pipe/monadic adapters", "[resolver]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x400000}, 0x4000, MemoryProtection::ExecuteReadWrite);

    // Place instruction at 0x400100: 48 8B 05 [disp32 to 0x401000] 48 85 C0
    // Next IP = 0x400107, target = 0x401000 => disp32 = 0x401000 - 0x400107 = 0xEF9
    const std::array<std::byte, 10> code{
        std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
        std::byte{0xF9}, std::byte{0x0E}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}};
    backend->poke_bytes(Address{0x400100}, code);

    // At 0x401000: pointer to object at 0x402000
    backend->poke_value<std::uint64_t>(Address{0x401000}, 0x402000ULL);
    // At 0x402000 + 0x120: int hp = 9001
    backend->poke_value<std::int32_t>(Address{0x402120}, 9001);

    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64);
    Scanner scanner{proc};
    const AddressRange mod_range{Address{0x400000}, 0x4000};
    constexpr Pattern sig = "48 8B 05 ?? ?? ?? ?? 48 85 C0"_sig;

    // 1. Fluent dot-chaining via AddressCursor
    Result<int> hp1 = scanner.find_unique_cursor(mod_range, sig)
                          .rel32(3, 7)
                          .deref()
                          .offset(0x120)
                          .read<int>();
    REQUIRE(hp1.has_value());
    REQUIRE(*hp1 == 9001);

    // 2. Pipe (|) operator chaining
    Result<int> hp2 = scanner.find_unique(mod_range, sig) | bind_process(proc) |
                      resolve::rel32(3, 7) | resolve::deref | resolve::offset(0x120) | tessera::read<int>;
    REQUIRE(hp2.has_value());
    REQUIRE(*hp2 == 9001);

    // 3. std::expected monadic chaining (transform / and_then)
    Result<int> hp3 = scanner.find_unique(mod_range, sig)
                          .transform(bind_process(proc))
                          .and_then(resolve::rel32(3, 7))
                          .and_then(resolve::deref)
                          .and_then(resolve::offset(0x120))
                          .and_then(tessera::read<int>);
    REQUIRE(hp3.has_value());
    REQUIRE(*hp3 == 9001);

    // follow_rip on 48 8B 05 disp32 resolves to 0x401000
    auto rip_target = ProcessAddress{proc, Address{0x400100}}.cursor().follow_rip().address();
    REQUIRE(rip_target.has_value());
    REQUIRE(*rip_target == Address{0x401000});

    auto stepped = ProcessAddress{proc, Address{0x400100}}.cursor().step_instructions().address();
    REQUIRE(stepped.has_value());
    REQUIRE(*stepped == Address{0x400107});
    auto rip_cursor = ProcessAddress{proc, Address{0x400100}}
                          .cursor().find_next_rip_relative(0x20).address();
    REQUIRE(rip_cursor.has_value());
    REQUIRE(*rip_cursor == Address{0x400100});
    auto operand_target = ProcessAddress{proc, Address{0x400100}}
                              .cursor().resolve_operand_target().address();
    REQUIRE(operand_target.has_value());
    REQUIRE(*operand_target == Address{0x401000});

    // Decoder-backed call discovery and bounded thunk-chain following.
    const std::int32_t call_disp = 0x401200 - (0x400305);
    backend->poke_value<std::uint8_t>(Address{0x400300}, 0xE8u);
    backend->poke_value<std::int32_t>(Address{0x400301}, call_disp);
    auto next_call = ProcessAddress{proc, Address{0x400300}}
                         .cursor().find_next_call(0x20).address();
    REQUIRE(next_call.has_value());
    REQUIRE(*next_call == Address{0x400300});
    auto call_target = ProcessAddress{proc, Address{0x400300}}
                           .cursor().resolve_operand_target().address();
    REQUIRE(call_target.has_value());
    REQUIRE(*call_target == Address{0x401200});

    const std::int32_t thunk_disp = 0x400350 - (0x400315);
    backend->poke_value<std::uint8_t>(Address{0x400310}, 0xE9u);
    backend->poke_value<std::int32_t>(Address{0x400311}, thunk_disp);
    backend->poke_value<std::uint8_t>(Address{0x400350}, 0x90u);
    auto thunk_end = ProcessAddress{proc, Address{0x400310}}
                         .cursor().resolve_thunk_chain().address();
    REQUIRE(thunk_end.has_value());
    REQUIRE(*thunk_end == Address{0x400350});

    // Cheat-Engine style pointer_chain: [[base + 0x10] + 0x20] + 0x30 (last offset only added)
    backend->poke_value<std::uint64_t>(Address{0x403010}, 0x403100ULL);
    backend->poke_value<std::uint64_t>(Address{0x403120}, 0x403200ULL);
    auto chain_end = ProcessAddress{proc, Address{0x403000}}
                         .cursor()
                         .pointer_chain(0x10, 0x20, 0x30)
                         .address();
    REQUIRE(chain_end.has_value());
    REQUIRE(*chain_end == Address{0x403230});

    // x86 abs32 resolution
    Process proc_x86 = FakeMemoryBackend::make_process(backend, Architecture::X86);
    backend->poke_value<std::uint8_t>(Address{0x400200}, 0xA1u); // mov eax, [abs32]
    backend->poke_value<std::uint32_t>(Address{0x400201}, 0x00401500u);
    auto abs_res = ProcessAddress{proc_x86, Address{0x400200}}.cursor().abs32(1).address();
    REQUIRE(abs_res.has_value());
    REQUIRE(*abs_res == Address{0x00401500});

    auto rva_res = resolve::abs32_to_rva(
        ProcessAddress{proc_x86, Address{0x400200}}, 1, 0x00400000ULL);
    REQUIRE(rva_res.has_value());
    REQUIRE(rva_res->value() == 0x1500u);
}

TEST_CASE("Resolver rejects overflowing instruction and operand offsets", "[resolver][safety]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x400000}, 0x1000, MemoryProtection::ReadWrite);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    ProcessAddress address{process, Address{0x400100}};

    auto bad_rel32 = resolve::rel32(
        (std::numeric_limits<std::size_t>::max)(), 5)(address);
    REQUIRE_FALSE(bad_rel32.has_value());
    REQUIRE(bad_rel32.error().code == ErrorCode::InvalidArgument);

    auto bad_instruction_length = resolve::rel32(2, 5)(address);
    REQUIRE_FALSE(bad_instruction_length.has_value());
    REQUIRE(bad_instruction_length.error().code == ErrorCode::InvalidArgument);
}

TEST_CASE("PE parser rejects malformed headers and reports missing sections and exports", "[module][pe][safety]") {
    using namespace tessera;

    std::vector<std::byte> bytes(0x600);
    const auto put16 = [&](std::size_t offset, std::uint16_t value) {
        bytes[offset] = static_cast<std::byte>(value & 0xFFu);
        bytes[offset + 1] = static_cast<std::byte>((value >> 8u) & 0xFFu);
    };
    const auto put32 = [&](std::size_t offset, std::uint32_t value) {
        for (std::size_t i = 0; i < 4; ++i) {
            bytes[offset + i] = static_cast<std::byte>((value >> (i * 8u)) & 0xFFu);
        }
    };
    const auto put64 = [&](std::size_t offset, std::uint64_t value) {
        for (std::size_t i = 0; i < 8; ++i) {
            bytes[offset + i] = static_cast<std::byte>((value >> (i * 8u)) & 0xFFu);
        }
    };

    put16(0x00, 0x5A4D);
    put32(0x3C, 0x80);
    put32(0x80, 0x00004550);
    put16(0x84, 0x8664);
    put16(0x86, 2);
    put32(0x88, 0x12345678);
    put16(0x94, 0xF0);
    put16(0x98, 0x020B);
    put32(0x98 + 16, 0x1000);
    put64(0x98 + 24, 0x140000000ull);
    put32(0x98 + 32, 0x1000);
    put32(0x98 + 36, 0x200);
    put32(0x98 + 56, 0x3000);
    put32(0x98 + 60, 0x200);
    put32(0x98 + 108, 16);
    put32(0x130, 0x2000); // Base relocation directory RVA
    put32(0x134, 12);     // One relocation block with two entries

    constexpr std::size_t section = 0x188;
    bytes[section] = std::byte{'.'};
    bytes[section + 1] = std::byte{'t'};
    bytes[section + 2] = std::byte{'e'};
    bytes[section + 3] = std::byte{'x'};
    bytes[section + 4] = std::byte{'t'};
    put32(section + 8, 0x100);
    put32(section + 12, 0x1000);
    put32(section + 16, 0x200);
    put32(section + 20, 0x200);
    put32(section + 36, 0x60000020);

    constexpr std::size_t reloc_section = section + 40;
    bytes[reloc_section] = std::byte{'.'};
    bytes[reloc_section + 1] = std::byte{'r'};
    bytes[reloc_section + 2] = std::byte{'e'};
    bytes[reloc_section + 3] = std::byte{'l'};
    bytes[reloc_section + 4] = std::byte{'o'};
    bytes[reloc_section + 5] = std::byte{'c'};
    put32(reloc_section + 8, 0x100);
    put32(reloc_section + 12, 0x2000);
    put32(reloc_section + 16, 0x200);
    put32(reloc_section + 20, 0x400);
    put32(reloc_section + 36, 0x42000040);

    put64(0x210, 0x140001234ULL); // Pointer at .text RVA 0x1010
    put32(0x400, 0x1000);          // Relocation page RVA
    put32(0x404, 12);              // Block size
    put16(0x408, 0xA010);           // DIR64 at page offset 0x10
    put16(0x40A, 0x0000);           // ABSOLUTE padding entry

    auto image = PeImage::from_raw_bytes(bytes);
    REQUIRE(image.has_value());
    REQUIRE(image->find_section(".text").has_value());
    REQUIRE_FALSE(image->find_section(".missing").has_value());
    REQUIRE_FALSE(image->find_export("MissingExport").has_value());
    REQUIRE(image->relocations().size() == 1);
    REQUIRE(image->relocations()[0].location == Rva{0x1010});
    REQUIRE(image->relocations()[0].type == 10u);

    // The same logical image must parse consistently from a raw file and a
    // mapped image after section raw data is placed at its virtual RVA.
    using namespace tessera::testing;
    auto mapped_backend = std::make_shared<FakeMemoryBackend>();
    mapped_backend->map_region(Address{0x500000}, 0x3000, MemoryProtection::ExecuteReadWrite);
    mapped_backend->poke_bytes(Address{0x500000}, std::span<const std::byte>{bytes}.first(0x200));
    mapped_backend->poke_bytes(Address{0x501000}, std::span<const std::byte>{bytes}.subspan(0x200, 0x200));
    mapped_backend->poke_bytes(Address{0x502000}, std::span<const std::byte>{bytes}.subspan(0x400, 0x200));
    mapped_backend->poke_value<std::uint64_t>(Address{0x501010}, 0x501234ULL);
    Process mapped_process = FakeMemoryBackend::make_process(mapped_backend, Architecture::X64);
    auto mapped_image = PeImage::from_memory(mapped_process, Address{0x500000});
    REQUIRE(mapped_image.has_value());
    REQUIRE(mapped_image->machine() == image->machine());
    REQUIRE(mapped_image->kind() == image->kind());
    REQUIRE(mapped_image->image_base() == image->image_base());
    REQUIRE(mapped_image->size_of_image() == image->size_of_image());
    REQUIRE(mapped_image->sections().size() == image->sections().size());
    REQUIRE(mapped_image->sections()[0].name == image->sections()[0].name);
    REQUIRE(mapped_image->sections()[0].rva == image->sections()[0].rva);
    REQUIRE(mapped_image->relocations().size() == 1);
    REQUIRE(mapped_image->relocations()[0].location == Rva{0x1010});
    auto relocated_refs = xref::find_relocated_pointer_refs(
        mapped_process, Address{0x500000}, *mapped_image, Address{0x501234});
    REQUIRE(relocated_refs.has_value());
    REQUIRE(relocated_refs->size() == 1);
    REQUIRE(relocated_refs->front() == Address{0x501010});

    auto malformed_reloc_block = bytes;
    malformed_reloc_block[0x404] = std::byte{0x07};
    malformed_reloc_block[0x405] = std::byte{0x00};
    malformed_reloc_block[0x406] = std::byte{0x00};
    malformed_reloc_block[0x407] = std::byte{0x00};
    REQUIRE_FALSE(PeImage::from_raw_bytes(malformed_reloc_block).has_value());

    auto out_of_bounds_reloc_dir = bytes;
    out_of_bounds_reloc_dir[0x134] = std::byte{0xFF};
    out_of_bounds_reloc_dir[0x135] = std::byte{0xFF};
    out_of_bounds_reloc_dir[0x136] = std::byte{0xFF};
    out_of_bounds_reloc_dir[0x137] = std::byte{0xFF};
    REQUIRE_FALSE(PeImage::from_raw_bytes(out_of_bounds_reloc_dir).has_value());

    auto malformed_lfanew = bytes;
    malformed_lfanew[0x3C] = std::byte{0xF0};
    malformed_lfanew[0x3D] = std::byte{0xFF};
    malformed_lfanew[0x3E] = std::byte{0xFF};
    malformed_lfanew[0x3F] = std::byte{0xFF};
    REQUIRE_FALSE(PeImage::from_raw_bytes(malformed_lfanew).has_value());

    auto out_of_image_section = bytes;
    out_of_image_section[section + 12] = std::byte{0x00};
    out_of_image_section[section + 13] = std::byte{0x30};
    out_of_image_section[section + 14] = std::byte{0x00};
    out_of_image_section[section + 15] = std::byte{0x00};
    REQUIRE_FALSE(PeImage::from_raw_bytes(out_of_image_section).has_value());
}
