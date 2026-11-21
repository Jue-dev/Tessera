#include <catch2/catch_test_macros.hpp>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/module/pe_file_backend.hpp"
#include "tessera/patch/disk_patch.hpp"
#include "tessera/scanner/scanner.hpp"

#ifndef TESSERA_TEST_FIXTURE_DIR
#error "TESSERA_TEST_FIXTURE_DIR must identify generated PE fixtures"
#endif

namespace {
std::filesystem::path fixture_path() {
 return std::filesystem::path{TESSERA_TEST_FIXTURE_DIR}/"rtti_virtual_branch_x64.dll";
}
std::filesystem::path temp_path(std::string_view suffix) {
 auto p=std::filesystem::temp_directory_path();
 p/=("tessera_disk_"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+std::string{suffix});
 return p;
}
}

TEST_CASE("PeFileBackend exposes bounded offline PE sections to existing readers and scanner","[pe][offline]"){
 using namespace tessera;
 auto path=fixture_path();REQUIRE(std::filesystem::exists(path));
 auto backend=PeFileBackend::open(path);REQUIRE(backend);
 auto process=(*backend)->make_process();REQUIRE(process);
 REQUIRE((*backend)->image().machine()==0x8664);
 auto text=(*backend)->image().find_section(".text");REQUIRE(text);
 auto va=(*backend)->rva_to_va(text->rva);REQUIRE(va);
 auto off=(*backend)->rva_to_file_offset(text->rva);REQUIRE(off);
 auto raw=filesystem::read_file_bytes(path);REQUIRE(raw);
 REQUIRE(*off<raw->size());
 MemoryReader reader{*process};
 std::array<std::byte,8> bytes{};auto read=reader.read_exact(*va,bytes);REQUIRE(read);
 REQUIRE(std::equal(bytes.begin(),bytes.end(),raw->begin()+*off));
 auto pattern=Pattern::from_bytes(std::span<const std::byte>{bytes.data(),4});REQUIRE(pattern);
 Scanner scanner{*process};
 const auto range=AddressRange{*va,std::min<std::uint64_t>(text->raw_size,0x2000)};
 auto found=scanner.scan(range,*pattern);REQUIRE(found);
 REQUIRE(std::find(found->hits.begin(),found->hits.end(),*va)!=found->hits.end());
 auto query=backend.value()->query(*va);REQUIRE(query);
 REQUIRE(query->is_committed());REQUIRE(has_flag(query->protection,MemoryProtection::Execute));
 REQUIRE_FALSE(backend.value()->read(Address{backend.value()->base().value()+0x100000000ULL},bytes));
 REQUIRE_FALSE(backend.value()->write(*va,bytes));
}

TEST_CASE("DiskPatchTransaction validates expected bytes, backs up, updates checksum, and can reverse an edit","[patch][disk][transaction]"){
 using namespace tessera;
 auto source=fixture_path();REQUIRE(std::filesystem::exists(source));
 auto temp=temp_path(".dll");auto backup=temp;backup+=".bak";
 std::filesystem::copy_file(source,temp,std::filesystem::copy_options::overwrite_existing);
 auto raw=filesystem::read_file_bytes(temp);REQUIRE(raw);
 auto pe=PeImage::from_raw_bytes(*raw);REQUIRE(pe);
 auto text=pe->find_section(".text");REQUIRE(text);REQUIRE(text->raw_size>0);
 const std::uint64_t offset=text->raw_offset;
 const std::byte original=(*raw)[static_cast<std::size_t>(offset)];
 const std::byte replacement{static_cast<unsigned char>(std::to_integer<unsigned char>(original)^0x5au)};
 DiskPatchTransaction patch{temp};
 REQUIRE(patch.add_patch(offset,std::span<const std::byte>{&replacement,1},std::span<const std::byte>{&original,1}));
 auto report=patch.apply();REQUIRE(report);REQUIRE(report->edits.size()==1);REQUIRE(report->backup.has_value());
 REQUIRE(std::filesystem::exists(*report->backup));
 auto changed=filesystem::read_file_bytes(temp);REQUIRE(changed);REQUIRE((*changed)[offset]==replacement);
 REQUIRE(PeDiskPatcher::calculate_checksum(*changed));
 DiskPatchTransaction reverse{temp};
 REQUIRE(reverse.add_patch(offset,std::span<const std::byte>{&original,1},std::span<const std::byte>{&replacement,1}));
 REQUIRE(reverse.apply());
 auto reverted=filesystem::read_file_bytes(temp);REQUIRE(reverted);REQUIRE((*reverted)[offset]==original);
 REQUIRE(PeDiskPatcher::find_code_caves(*reverted,8));
 std::error_code ec;std::filesystem::remove(temp,ec);std::filesystem::remove(backup,ec);
}

TEST_CASE("DiskPatchTransaction requires explicit opt-in for a signed PE","[patch][disk][authenticode]"){
 using namespace tessera;
 auto source=fixture_path();REQUIRE(std::filesystem::exists(source));
 auto raw=filesystem::read_file_bytes(source);REQUIRE(raw);
 auto peoff=*reinterpret_cast<const std::uint32_t*>(raw->data()+0x3c);
 const std::size_t opt=static_cast<std::size_t>(peoff)+4u+20u;
 const auto magic=*reinterpret_cast<const std::uint16_t*>(raw->data()+opt);
 const std::size_t dd=opt+(magic==0x20b?112u:96u);
 const std::uint32_t cert_offset=static_cast<std::uint32_t>(raw->size());
 const std::uint32_t cert_size=8;
 raw->resize(raw->size()+cert_size,std::byte{0});
 std::memcpy(raw->data()+dd+4u*8u,&cert_offset,sizeof(cert_offset));
 std::memcpy(raw->data()+dd+4u*8u+4u,&cert_size,sizeof(cert_size));
 auto temp=temp_path("_signed.dll");{
  std::ofstream out(temp,std::ios::binary);out.write(reinterpret_cast<const char*>(raw->data()),static_cast<std::streamsize>(raw->size()));
 }
 auto pe=PeImage::from_file(temp);REQUIRE(pe);auto text=pe->find_section(".text");REQUIRE(text);
 const std::byte old=(*raw)[text->raw_offset];const std::byte next{0x7f};
 DiskPatchTransaction denied{temp};
 REQUIRE(denied.add_patch(text->raw_offset,std::span<const std::byte>{&next,1},std::span<const std::byte>{&old,1}));
 auto denied_report=denied.apply();REQUIRE_FALSE(denied_report);REQUIRE(denied_report.error().code==ErrorCode::AccessDenied);
 DiskPatchOptions allow{};allow.create_backup=false;allow.strip_signature=true;
 DiskPatchTransaction permitted{temp,allow};
 REQUIRE(permitted.add_patch(text->raw_offset,std::span<const std::byte>{&next,1},std::span<const std::byte>{&old,1}));
 auto report=permitted.apply();REQUIRE(report);REQUIRE(report->signature_present_before);REQUIRE(report->signature_directory_cleared);
 std::error_code ec;std::filesystem::remove(temp,ec);
}
