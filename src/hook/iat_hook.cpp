#include "tessera/hook/iat_hook.hpp"
#include <array>
#include <cctype>
#include <cstring>
#include <utility>
#include "tessera/memory/memory_backend.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/protection_scope.hpp"
#include "tessera/module/pe_image.hpp"
namespace tessera { namespace {
bool eqci(std::string_view a,std::string_view b)noexcept{if(a.size()!=b.size())return false;for(size_t i=0;i<a.size();++i)if(std::tolower((unsigned char)a[i])!=std::tolower((unsigned char)b[i]))return false;return true;}
Status put(const Process&p,Address s,Address v){std::array<std::byte,8>b{};auto n=p.pointer_size();auto raw=v.value();std::memcpy(b.data(),&raw,n);auto w=memory_backend(p).write(s,{b.data(),n});if(!w)return std::unexpected(w.error());if(*w!=n)return fail(ErrorCode::PartialTransfer,"IatHook::write");return ok();}
}
IatHook::IatHook(IatHook&&o)noexcept:process_(std::move(o.process_)),slot_(std::exchange(o.slot_,{})),original_(std::exchange(o.original_,{})),replacement_(std::exchange(o.replacement_,{})),installed_(std::exchange(o.installed_,false)){}
IatHook::~IatHook()noexcept{if(installed_)(void)restore();}
Result<IatHook> IatHook::install(const Process&p,Address base,std::string_view dll,std::string_view fn,Address repl){
 if(base.is_null()||repl.is_null()||dll.empty()||fn.empty()||(p.pointer_size()!=4&&p.pointer_size()!=8)||(p.pointer_size()==4&&repl.value()>0xffffffffULL))return fail(ErrorCode::InvalidArgument,"IatHook::install");
 auto pe=PeImage::from_memory(p,base);if(!pe)return std::unexpected(pe.error());const ImportEntry* hit=nullptr;
 for(const auto&e:pe->imports())if(!e.by_ordinal&&eqci(e.module_name,dll)&&e.function_name==fn){hit=&e;break;}
 if(!hit)return fail(ErrorCode::NotFound,"IatHook::install");
 auto slot=base.add_rva(hit->iat_rva);if(!slot)return std::unexpected(slot.error());MemoryReader r{p};auto old=r.read_pointer(*slot);if(!old)return std::unexpected(old.error());
 auto scope=ProtectionScope::create(p,{*slot,p.pointer_size()},MemoryProtection::Read|MemoryProtection::Write);if(!scope)return std::unexpected(scope.error());
 auto w=put(p,*slot,repl);if(!w){
  // IAT entries are data pointers. Attempt to restore the original value even
  // after a failed/partial write, before restoring the page protection.
  (void)put(p,*slot,*old);
  (void)scope->restore();
  return std::unexpected(w.error());
 }
 auto rs=scope->restore();if(!rs){auto rollback=ProtectionScope::create(p,{*slot,p.pointer_size()},MemoryProtection::Read|MemoryProtection::Write);if(rollback){(void)put(p,*slot,*old);(void)rollback->restore();}(void)scope->restore();return std::unexpected(rs.error());}
 return IatHook{p,*slot,*old,repl};
}
Status IatHook::restore()noexcept{
 if(!installed_)return ok();MemoryReader r{process_};auto cur=r.read_pointer(slot_);if(!cur)return std::unexpected(cur.error());
 if(*cur!=replacement_)return fail(ErrorCode::Conflict,"IatHook::restore",0,"IAT slot no longer contains this hook");
 auto scope=ProtectionScope::create(process_,{slot_,process_.pointer_size()},MemoryProtection::Read|MemoryProtection::Write);if(!scope)return std::unexpected(scope.error());
 auto w=put(process_,slot_,original_);if(!w){(void)scope->restore();return w;}installed_=false;auto rs=scope->restore();if(!rs){(void)scope->restore();return rs;}return ok();
}
} // namespace tessera
