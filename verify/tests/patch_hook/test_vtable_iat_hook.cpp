#include <catch2/catch_test_macros.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include "FakeMemoryBackend.hpp"
#include "tessera/hook/vtable_hook.hpp"
#include "tessera/hook/iat_hook.hpp"
#include "tessera/memory/memory_reader.hpp"

namespace {
struct VirtualSample { virtual int first(){return 11;} virtual int second(){return 22;} };
int replacement_first(VirtualSample*){return 99;}
template<class T>void put(std::vector<std::byte>& b,std::size_t off,T v){std::memcpy(b.data()+off,&v,sizeof(v));}
std::vector<std::byte> mapped_pe_with_import(){
 std::vector<std::byte>b(0x4000,std::byte{0});
 put(b,0,std::uint16_t{0x5a4d});put(b,0x3c,std::uint32_t{0x80});put(b,0x80,std::uint32_t{0x00004550});
 const std::size_t coff=0x84,opt=0x98,sec=opt+240;
 put(b,coff,std::uint16_t{0x8664});put(b,coff+2,std::uint16_t{1});put(b,coff+16,std::uint16_t{240});
 put(b,opt,std::uint16_t{0x20b});put(b,opt+24,std::uint64_t{0x140000000});
 put(b,opt+32,std::uint32_t{0x1000});put(b,opt+36,std::uint32_t{0x200});put(b,opt+56,std::uint32_t{0x4000});
 put(b,opt+60,std::uint32_t{0x400});put(b,opt+108,std::uint32_t{16});
 put(b,opt+112+8,std::uint32_t{0x1100});put(b,opt+112+12,std::uint32_t{40});
 std::memcpy(b.data()+sec,".rdata",6);put(b,sec+8,std::uint32_t{0x2000});put(b,sec+12,std::uint32_t{0x1000});
 put(b,sec+16,std::uint32_t{0x2000});put(b,sec+20,std::uint32_t{0x400});put(b,sec+36,std::uint32_t{0xc0000040});
 put(b,0x1100,std::uint32_t{0x1200});put(b,0x110c,std::uint32_t{0x1150});put(b,0x1110,std::uint32_t{0x1300});
 std::memcpy(b.data()+0x1150,"KERNEL32.dll",13);put(b,0x1200,std::uint64_t{0x1400});put(b,0x1208,std::uint64_t{0});
 put(b,0x1300,std::uint64_t{0x7ff012340000ULL});put(b,0x1308,std::uint64_t{0});put(b,0x1400,std::uint16_t{0});std::memcpy(b.data()+0x1402,"Sleep",6);
 return b;
}
}

TEST_CASE("VTableHook shadows a caller-bounded vftable and restores the original pointer","[hook][vtable]"){
 VirtualSample object;REQUIRE(object.first()==11);
 auto created=tessera::VTableHook::create(&object,2);REQUIRE(created);
 auto hook=std::move(*created);auto original=hook.hook(0,&replacement_first);REQUIRE(original);
 REQUIRE(*original(&object)==11);REQUIRE(hook.install());REQUIRE(hook.installed());
 REQUIRE(object.first()==99);REQUIRE(hook.restore());REQUIRE(object.first()==11);REQUIRE_FALSE(hook.installed());
}

TEST_CASE("IatHook installs and rolls back a synthetic mapped PE import","[hook][iat]"){
 using namespace tessera;using namespace tessera::testing;
 constexpr Address base{0x140000000ULL};auto backend=std::make_shared<FakeMemoryBackend>();
 backend->map_region(base,0x4000,MemoryProtection::ReadWrite,MemoryType::Image);
 auto image=mapped_pe_with_import();backend->poke_bytes(base,image);Process process=FakeMemoryBackend::make_process(backend,Architecture::X64);
 auto parsed=PeImage::from_memory(process,base);REQUIRE(parsed);REQUIRE(parsed->imports().size()==1);
 auto hook=IatHook::install(process,base,"kernel32.dll","Sleep",Address{0x7ff055550000ULL});REQUIRE(hook);REQUIRE(hook->installed());
 MemoryReader reader{process};auto slot=base.add_rva(Rva{0x1300});REQUIRE(slot);REQUIRE(reader.read_pointer(*slot).value()==Address{0x7ff055550000ULL});
 REQUIRE(hook->original()==Address{0x7ff012340000ULL});REQUIRE(hook->restore());REQUIRE(reader.read_pointer(*slot).value()==Address{0x7ff012340000ULL});
}
