#pragma once
#include <string_view>
#include <utility>
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/process/process.hpp"
namespace tessera {
class IatHook {
public:
 IatHook(const IatHook&)=delete;IatHook& operator=(const IatHook&)=delete;IatHook& operator=(IatHook&&)=delete;
 IatHook(IatHook&&)noexcept;~IatHook()noexcept;
 [[nodiscard]] static Result<IatHook> install(const Process&,Address,std::string_view,std::string_view,Address);
 [[nodiscard]] Status restore()noexcept;
 [[nodiscard]] Address original()const noexcept{return original_;}
 [[nodiscard]] Address slot()const noexcept{return slot_;}
 [[nodiscard]] bool installed()const noexcept{return installed_;}
private:
 IatHook(Process p,Address s,Address o,Address r)noexcept:process_(std::move(p)),slot_(s),original_(o),replacement_(r),installed_(true){}
 Process process_;Address slot_{},original_{},replacement_{};bool installed_=false;
};
} // namespace tessera
