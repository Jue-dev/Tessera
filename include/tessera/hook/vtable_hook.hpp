#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>
#include "tessera/core/result.hpp"
namespace tessera {
class VTableHook {
public:
 VTableHook(const VTableHook&)=delete; VTableHook& operator=(const VTableHook&)=delete; VTableHook& operator=(VTableHook&&)=delete;
 VTableHook(VTableHook&& o) noexcept : object_(std::exchange(o.object_,nullptr)), original_(std::exchange(o.original_,nullptr)), originals_(std::move(o.originals_)), shadow_(std::move(o.shadow_)), active_(std::exchange(o.active_,false)) {}
 ~VTableHook() noexcept { if(active_)(void)restore(); }
 [[nodiscard]] static Result<VTableHook> create(void* object,std::size_t count){
  if(!object||!count||count>4096)return fail(ErrorCode::InvalidArgument,"VTableHook::create");
  auto loc=reinterpret_cast<void***>(object);if(!*loc)return fail(ErrorCode::InvalidArgument,"VTableHook::create");
  try{std::vector<void*> a(*loc,*loc+count);auto b=a;return VTableHook(object,*loc,std::move(a),std::move(b));}
  catch(const std::bad_alloc&){return fail(ErrorCode::OutOfMemory,"VTableHook::create");}
 }
 [[nodiscard]] Result<void*> set_slot(std::size_t i,void* replacement) noexcept{
  if(active_)return fail(ErrorCode::Conflict,"VTableHook::set_slot",0,"Restore the object before changing shadow slots");
  if(i>=shadow_.size()||!replacement)return fail(ErrorCode::OutOfRange,"VTableHook::set_slot");
  auto old=originals_[i];shadow_[i]=replacement;return old;
 }
 template<class Fn> requires(std::is_pointer_v<Fn>&&std::is_function_v<std::remove_pointer_t<Fn>>)
 [[nodiscard]] Result<Fn> hook(std::size_t i,Fn replacement) noexcept{
  auto r=set_slot(i,reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(replacement)));
  if(!r)return std::unexpected(r.error());return reinterpret_cast<Fn>(reinterpret_cast<std::uintptr_t>(*r));
 }
 [[nodiscard]] Status install() noexcept{
  if(!object_||active_)return fail(ErrorCode::InvalidArgument,"VTableHook::install");
  auto& slot=*reinterpret_cast<void**>(object_);void* expected=original_;
  if(!std::atomic_ref<void*>{slot}.compare_exchange_strong(expected,shadow_.data(),std::memory_order_acq_rel))
   return fail(ErrorCode::Conflict,"VTableHook::install",0,"Object vftable changed");
  active_=true;return ok();
 }
 [[nodiscard]] Status restore() noexcept{
  if(!active_)return ok();auto& slot=*reinterpret_cast<void**>(object_);void* expected=shadow_.data();
  if(!std::atomic_ref<void*>{slot}.compare_exchange_strong(expected,original_,std::memory_order_acq_rel))
   return fail(ErrorCode::Conflict,"VTableHook::restore",0,"Object vftable is no longer owned by this hook");
  active_=false;return ok();
 }
 [[nodiscard]] Result<void*> original(std::size_t i)const noexcept{if(i>=originals_.size())return fail(ErrorCode::OutOfRange,"VTableHook::original");return originals_[i];}
 [[nodiscard]] bool installed()const noexcept{return active_;} [[nodiscard]] std::size_t slot_count()const noexcept{return shadow_.size();}
private:
 VTableHook(void* o,void** v,std::vector<void*> a,std::vector<void*> b)noexcept:object_(o),original_(v),originals_(std::move(a)),shadow_(std::move(b)){}
 void* object_{};void** original_{};std::vector<void*> originals_{},shadow_{};bool active_=false;
};
} // namespace tessera
