#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include "tessera/core/error.hpp"
#include "tessera/filesystem/filesystem.hpp"
#include "tessera/json/json.hpp"
#include "tessera/module/pe_file_backend.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/targets/target_profile_json.hpp"
#include "tessera/targets/target_runtime.hpp"

namespace {
using namespace tessera;
void show_error(const Error& e) {
    std::cerr << error_code_name(e.code) << ": " << e.operation;
    if (!e.detail.empty()) std::cerr << ": " << e.detail;
    std::cerr << '\n';
}
std::string q(std::string_view s) {
    std::string out{"\""}; constexpr char h[] = "0123456789abcdef";
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 32u) { out += "\\u00"; out += h[c >> 4u]; out += h[c & 15u]; }
            else out += static_cast<char>(c);
        }
    }
    out += '"'; return out;
}
std::string hx(std::uint64_t v) {
    constexpr char d[] = "0123456789abcdef"; std::string s;
    do { s.insert(s.begin(), d[v & 15u]); v >>= 4u; } while (v);
    return "0x" + s;
}
template<class T> bool rd(std::span<const std::byte> b, std::size_t o, T& v) {
    if (o > b.size() || sizeof(T) > b.size() - o) return false;
    std::memcpy(&v, b.data() + o, sizeof(T)); return true;
}
bool is_signed(std::span<const std::byte> b) {
    std::uint32_t pe = 0; std::uint16_t os = 0, magic = 0;
    if (!rd(b, 0x3c, pe)) return false;
    const auto coff = static_cast<std::size_t>(pe) + 4u;
    if (!rd(b, coff + 16u, os) || !rd(b, coff + 20u, magic)) return false;
    const auto dd = coff + 20u + (magic == 0x20b ? 112u : magic == 0x10b ? 96u : 0u);
    if (dd == coff + 20u || os < 68u || dd + 40u > coff + 20u + os) return false;
    std::uint32_t off = 0, size = 0;
    return rd(b, dd + 32u, off) && rd(b, dd + 36u, size) &&
           off && size && off <= b.size() && size <= b.size() - off;
}
int inspect(const std::filesystem::path& file, bool json) {
    auto b = PeFileBackend::open(file); if (!b) { show_error(b.error()); return 2; }
    auto raw = filesystem::read_file_bytes(file); if (!raw) { show_error(raw.error()); return 2; }
    const auto& pe = (*b)->image();
    if (!json) {
        std::cout << "PE " << (pe.kind() == PeKind::Pe32Plus ? "x64" : "x86")
                  << " imageBase=" << hx(pe.image_base()) << " imageSize=" << pe.size_of_image() << '\n'
                  << "Authenticode certificate table: " << (is_signed(*raw) ? "present" : "absent") << '\n';
        for (const auto& s : pe.sections())
            std::cout << s.name << " RVA=" << hx(s.rva.value()) << " raw=" << s.raw_size
                      << " " << (s.is_readable() ? "R" : "-") << (s.is_writable() ? "W" : "-")
                      << (s.is_executable() ? "X" : "-") << '\n';
        std::cout << "Exports: " << pe.exports().size() << " Imports: " << pe.imports().size() << '\n';
        return 0;
    }
    std::cout << "{\"file\":" << q(file.filename().string())
              << ",\"architecture\":" << q(pe.kind() == PeKind::Pe32Plus ? "x64" : "x86")
              << ",\"machine\":" << pe.machine() << ",\"imageBase\":" << q(hx(pe.image_base()))
              << ",\"entryPointRva\":" << q(hx(pe.entry_point().value()))
              << ",\"sizeOfImage\":" << pe.size_of_image()
              << ",\"timestamp\":" << pe.timestamp()
              << ",\"checksum\":" << pe.checksum()
              << ",\"signaturePresent\":" << (is_signed(*raw) ? "true" : "false")
              << ",\"exportCount\":" << pe.exports().size() << ",\"importCount\":" << pe.imports().size()
              << ",\"sections\":[";
    bool first = true;
    for (const auto& s : pe.sections()) {
        if (!first) std::cout << ','; first = false;
        std::cout << "{\"name\":" << q(s.name) << ",\"rva\":" << q(hx(s.rva.value()))
                  << ",\"virtualSize\":" << s.virtual_size << ",\"rawOffset\":" << s.raw_offset
                  << ",\"rawSize\":" << s.raw_size << ",\"read\":" << (s.is_readable()?"true":"false")
                  << ",\"write\":" << (s.is_writable()?"true":"false")
                  << ",\"execute\":" << (s.is_executable()?"true":"false") << '}';
    }
    std::cout << "]}\n"; return 0;
}
int scan(const std::filesystem::path& file, std::string_view sig, std::string_view section, bool json) {
    auto p = Pattern::parse(sig); if (!p) { show_error(p.error()); return 2; }
    auto b = PeFileBackend::open(file); if (!b) { show_error(b.error()); return 2; }
    auto proc = (*b)->make_process(); if (!proc) { show_error(proc.error()); return 2; }
    Scanner scanner{*proc}; std::vector<Address> hits;
    const auto& pe = (*b)->image();
    for (const auto& s : pe.sections()) {
        if ((!section.empty() && section != s.name) || s.raw_size == 0 || s.rva.value() >= pe.size_of_image()) continue;
        auto va = (*b)->rva_to_va(s.rva); if (!va) continue;
        const auto n = (std::min)(static_cast<std::uint64_t>(s.raw_size),
            static_cast<std::uint64_t>(pe.size_of_image()) - s.rva.value());
        auto result = scanner.scan(AddressRange{*va, n}, *p);
        if (!result) { if (!json) show_error(result.error()); continue; }
        hits.insert(hits.end(), result->hits.begin(), result->hits.end());
    }
    std::sort(hits.begin(), hits.end());
    if (json) {
        std::cout << "{\"count\":" << hits.size() << ",\"matches\":[";
        for (std::size_t i=0;i<hits.size();++i) {
            if (i) std::cout << ',';
            std::cout << "{\"va\":" << q(hx(hits[i].value()))
                      << ",\"rva\":" << q(hx(hits[i].value()-(*b)->base().value())) << '}';
        }
        std::cout << "]}\n";
    } else {
        for (auto h : hits) std::cout << hx(h.value()) << " RVA " << hx(h.value()-(*b)->base().value()) << '\n';
        std::cout << hits.size() << " match(es)\n";
    }
    return 0;
}
int rtti_cmd(const std::filesystem::path& file, bool json) {
    auto b=PeFileBackend::open(file); if(!b){show_error(b.error());return 2;}
    auto proc=(*b)->make_process();if(!proc){show_error(proc.error());return 2;}
    auto cat=rtti::RttiCatalog::discover_all(*proc,{(*b)->base(),(*b)->image().size_of_image()},&(*b)->image());
    if(!cat){show_error(cat.error());return 2;}
    if(json){
        std::cout<<"{\"count\":"<<cat->classes().size()<<",\"classes\":[";
        bool first=true;for(const auto& c:cat->classes()){
            if(!first)std::cout<<',';first=false;
            std::cout<<"{\"name\":"<<q(c.demangled_name)<<",\"mangledName\":"<<q(c.mangled_name)
                     <<",\"vftableRva\":"<<q(hx(c.vftable_rva.value()))
                     <<",\"virtualMethodCount\":"<<c.virtual_methods.size()
                     <<",\"baseClassCount\":"<<c.base_classes.size()<<'}';
        }std::cout<<"]}\n";
    }else{
        for(const auto& c:cat->classes())std::cout<<c.demangled_name<<" vftable RVA "<<hx(c.vftable_rva.value())<<'\n';
        std::cout<<cat->classes().size()<<" RTTI class(es)\n";
    }return 0;
}
Result<targets::TargetProfile> load_profile(const std::filesystem::path& file) {
    auto text=filesystem::read_file_utf8(file);if(!text)return std::unexpected(text.error());
    auto parsed=json::parse(*text);if(!parsed)return std::unexpected(parsed.error());
    return targets::deserialize_target_profile_from_json(*parsed);
}
struct OfflineTarget { std::shared_ptr<PeFileBackend> backend; Process process; targets::TargetModuleContext module; };
Result<OfflineTarget> target_for(const std::filesystem::path& file) {
    auto b=PeFileBackend::open(file);if(!b)return std::unexpected(b.error());
    auto p=(*b)->make_process();if(!p)return std::unexpected(p.error());
    targets::TargetFingerprinter fp;auto f=fp.fingerprint_file("main",file);if(!f)return std::unexpected(f.error());
    targets::TargetModuleContext m{};m.module_id="main";m.file_name=file.filename().string();
    m.range={(*b)->base(),(*b)->image().size_of_image()};m.fingerprint=std::move(*f);m.pe_image=(*b)->image();
    return OfflineTarget{std::move(*b),std::move(*p),std::move(m)};
}
std::string_view status(targets::ResolutionStatus s) {
    using S=targets::ResolutionStatus;
    switch(s){
    case S::VerifiedExactBuild:return "verified_exact_build";
    case S::VerifiedCompatibleBuild:return "verified_compatible_build";
    case S::CandidateFound:return "candidate_found";
    case S::NeedsReview:return "needs_review";
    case S::Ambiguous:return "ambiguous";
    case S::Stale:return "stale";
    case S::NotFound:return "not_found";
    case S::IncompatibleTarget:return "incompatible_target";
    }return "unknown";
}
std::string trace_json(const targets::ResolutionTrace& t) {
    std::string s{"["};for(std::size_t i=0;i<t.steps.size();++i){
        if(i)s+=',';const auto& x=t.steps[i];
        s+="{\"stage\":"+q(x.stage)+",\"status\":"+q(status(x.status))+",\"detail\":"+q(x.detail)+"}";
    }return s+"]";
}
std::vector<std::string> ids(const targets::TargetProfile& p) {
    std::vector<std::string> v;for(const auto& b:p.builds)for(const auto& a:b.addresses)
        if(std::find(v.begin(),v.end(),a.id)==v.end())v.push_back(a.id);return v;
}
int profile_verify(const std::filesystem::path& profile_file,const std::filesystem::path& pe_file,bool json) {
    auto p=load_profile(profile_file);if(!p){show_error(p.error());return 2;}
    auto t=target_for(pe_file);if(!t){show_error(t.error());return 2;}
    targets::AddressResolver resolver{t->process,{t->module}};
    struct Entry{std::string id;targets::ResolutionOutcome r;targets::ResolutionTrace trace;};
    std::vector<Entry> entries;std::size_t resolved=0;
    for(const auto& id:ids(*p)){targets::ResolutionTrace trace;auto r=resolver.resolve_entry(*p,id,targets::PersistPolicy::ReadOnly,nullptr,&trace);
        if(r.verified())++resolved;entries.push_back({id,std::move(r),std::move(trace)});}
    const auto broken=entries.size()-resolved;
    if(json){
        std::cout<<"{\"applicationId\":"<<q(p->application.application_id)<<",\"total\":"<<entries.size()
                 <<",\"resolved\":"<<resolved<<",\"broken\":"<<broken<<",\"entries\":[";
        for(std::size_t i=0;i<entries.size();++i){if(i)std::cout<<',';const auto& e=entries[i];
            std::cout<<"{\"id\":"<<q(e.id)<<",\"status\":"<<q(status(e.r.status));
            if(e.r.candidate_rva)std::cout<<",\"candidateRva\":"<<q(hx(e.r.candidate_rva->value()));
            std::cout<<",\"resolution_trace\":"<<trace_json(e.trace)<<'}';}
        std::cout<<"]}\n";
    }else{
        std::cout<<resolved<<"/"<<entries.size()<<" addresses resolved\n";
        for(const auto& e:entries){std::cout<<e.id<<": "<<status(e.r.status)<<'\n';
            if(!e.r.verified())for(const auto& s:e.trace.steps)std::cout<<"  ["<<s.stage<<"] "<<s.detail<<'\n';}
    }return broken?1:0;
}
int profile_diff(const std::filesystem::path& pf,const std::filesystem::path& oldf,const std::filesystem::path& newf,bool json) {
    auto p=load_profile(pf);if(!p){show_error(p.error());return 2;}
    auto oldt=target_for(oldf);if(!oldt){show_error(oldt.error());return 2;}
    auto newt=target_for(newf);if(!newt){show_error(newt.error());return 2;}
    targets::AddressResolver oldr{oldt->process,{oldt->module}},newr{newt->process,{newt->module}};
    struct Change{std::string id;std::optional<Rva> before,after;targets::ResolutionStatus os,ns;};
    std::vector<Change> changes;std::size_t moved=0,broken=0;
    for(const auto& id:ids(*p)){auto a=oldr.resolve_entry(*p,id,targets::PersistPolicy::ReadOnly,nullptr);
        auto b=newr.resolve_entry(*p,id,targets::PersistPolicy::ReadOnly,nullptr);
        if(!a.verified()||!b.verified())++broken;else if(a.candidate_rva!=b.candidate_rva)++moved;
        changes.push_back({id,a.candidate_rva,b.candidate_rva,a.status,b.status});}
    if(json){
        std::cout<<"{\"total\":"<<changes.size()<<",\"moved\":"<<moved<<",\"broken\":"<<broken<<",\"entries\":[";
        for(std::size_t i=0;i<changes.size();++i){if(i)std::cout<<',';const auto& c=changes[i];
            std::cout<<"{\"id\":"<<q(c.id)<<",\"oldStatus\":"<<q(status(c.os))<<",\"newStatus\":"<<q(status(c.ns));
            if(c.before)std::cout<<",\"oldRva\":"<<q(hx(c.before->value()));
            if(c.after)std::cout<<",\"newRva\":"<<q(hx(c.after->value()));std::cout<<'}';}
        std::cout<<"]}\n";
    }else std::cout<<moved<<" moved, "<<broken<<" broken address(es)\n";
    return broken?1:0;
}
int export_symbols(const std::filesystem::path& file,const std::optional<std::filesystem::path>& profile_file) {
    auto b=PeFileBackend::open(file);if(!b){show_error(b.error());return 2;}const auto& pe=(*b)->image();
    std::cout<<"{\"schema\":\"tessera.symbols.v1\",\"binary\":"<<q(file.filename().string())
             <<",\"architecture\":"<<q(pe.kind()==PeKind::Pe32Plus?"x64":"x86")<<",\"exports\":[";
    bool first=true;for(const auto& e:pe.exports()){if(!first)std::cout<<',';first=false;
        std::cout<<"{\"name\":"<<q(e.name)<<",\"ordinal\":"<<e.ordinal<<",\"rva\":"<<q(hx(e.rva.value()))<<",\"forwarder\":";
        if(e.forwarder)std::cout<<q(*e.forwarder);else std::cout<<"null";std::cout<<'}';}
    auto proc=(*b)->make_process();if(!proc){show_error(proc.error());return 2;}
    auto cat=rtti::RttiCatalog::discover_all(*proc,{(*b)->base(),pe.size_of_image()},&pe);
    if(!cat){show_error(cat.error());return 2;}
    std::cout<<"],\"rtti\":[";first=true;
    for(const auto& c:cat->classes()){if(!first)std::cout<<',';first=false;
        std::cout<<"{\"name\":"<<q(c.demangled_name)<<",\"mangledName\":"<<q(c.mangled_name)
                 <<",\"vftableRva\":"<<q(hx(c.vftable_rva.value()))<<'}';}
    std::cout<<']';
    if(profile_file){auto p=load_profile(*profile_file);if(!p){show_error(p.error());return 2;}
        std::cout<<",\"profile\":{\"applicationId\":"<<q(p->application.application_id)<<",\"buildCount\":"<<p->builds.size()<<'}';}
    std::cout<<"}\n";return 0;
}
void usage(){
    std::cerr<<"tessera inspect <pe_file> [--json]\n"
      <<"tessera scan <pe_file> --pattern \"<sig>\" [--section .text] [--json]\n"
      <<"tessera rtti <pe_file> [--json]\n"
      <<"tessera profile verify <profile.json> <pe_file> [--json]\n"
      <<"tessera profile diff <profile.json> <old_pe> <new_pe> [--json]\n"
      <<"tessera export-symbols <pe_file> [--profile <profile.json>] --format json\n";
}
} // namespace
int main(int argc,char** argv){
    std::vector<std::string_view> a;bool json=false;
    for(int i=1;i<argc;++i){if(std::string_view{argv[i]}=="--json")json=true;else a.emplace_back(argv[i]);}
    if(a.empty()){usage();return 2;}
    if(a[0]=="inspect"&&a.size()==2)return inspect(std::string{a[1]},json);
    if(a[0]=="rtti"&&a.size()==2)return rtti_cmd(std::string{a[1]},json);
    if(a[0]=="scan"){
        std::filesystem::path file;std::string sig,section;
        for(std::size_t i=1;i<a.size();++i){
            if(a[i]=="--pattern"&&i+1<a.size())sig=a[++i];
            else if(a[i]=="--section"&&i+1<a.size())section=a[++i];
            else if(!a[i].starts_with("--")&&file.empty())file=std::string{a[i]};
            else{std::cerr<<"Invalid scan argument: "<<a[i]<<'\n';return 2;}}
        if(file.empty()||sig.empty()){usage();return 2;}return scan(file,sig,section,json);
    }
    if(a[0]=="profile"&&a.size()==4&&a[1]=="verify")return profile_verify(std::string{a[2]},std::string{a[3]},json);
    if(a[0]=="profile"&&a.size()==5&&a[1]=="diff")return profile_diff(std::string{a[2]},std::string{a[3]},std::string{a[4]},json);
    if(a[0]=="export-symbols"&&a.size()>=2){
        std::optional<std::filesystem::path> profile;bool format=false;
        for(std::size_t i=2;i<a.size();++i){
            if(a[i]=="--profile"&&i+1<a.size())profile=std::string{a[++i]};
            else if(a[i]=="--format"&&i+1<a.size())format=a[++i]=="json";
            else{std::cerr<<"Invalid export-symbols argument: "<<a[i]<<'\n';return 2;}}
        if(!format){std::cerr<<"export-symbols requires --format json\n";return 2;}
        return export_symbols(std::string{a[1]},profile);
    }
    usage();return 2;
}
