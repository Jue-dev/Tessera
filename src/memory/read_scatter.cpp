#include "tessera/memory/read_scatter.hpp"
#include <algorithm>
#include <new>
#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_backend.hpp"
namespace tessera {
Result<std::vector<MemoryReadResult>> read_scatter(const Process&p,std::span<const MemoryReadRequest> req,std::size_t gap,std::size_t max_size){
 if(!max_size)return fail(ErrorCode::InvalidArgument,"read_scatter");
 struct Item{size_t i;uint64_t b,e;};try{
 std::vector<MemoryReadResult> out(req.size());std::vector<Item> q;
 for(size_t i=0;i<req.size();++i){if(!req[i].size)continue;if(req[i].size>max_size){out[i].error=make_error(ErrorCode::OutOfRange,"read_scatter");continue;}if(req[i].address.is_null()){out[i].error=make_error(ErrorCode::NullAddress,"read_scatter");continue;}auto end=checked_add<uint64_t>(req[i].address.value(),req[i].size);if(!end){out[i].error=end.error();continue;}q.push_back({i,req[i].address.value(),*end});}
 std::sort(q.begin(),q.end(),[](auto&a,auto&b){return a.b<b.b;});const auto& backend=memory_backend(p);size_t cur=0;
 while(cur<q.size()){size_t last=cur+1;uint64_t begin=q[cur].b,end=q[cur].e;
  while(last<q.size()){uint64_t d=q[last].b>end?q[last].b-end:0;if(d>gap||q[last].e-begin>max_size)break;end=std::max(end,q[last].e);++last;}
  std::vector<std::byte> batch(static_cast<size_t>(end-begin));auto got=backend.read(Address{begin},batch);
  if(got&&*got==batch.size()){for(size_t j=cur;j<last;++j){auto x=q[j];auto off=static_cast<size_t>(x.b-begin);out[x.i].bytes.assign(batch.begin()+off,batch.begin()+off+req[x.i].size);}}
  else{for(size_t j=cur;j<last;++j){auto x=q[j];std::vector<std::byte>b(req[x.i].size);auto r=backend.read(req[x.i].address,b);if(!r)out[x.i].error=r.error();else{if(*r<b.size()){b.resize(*r);out[x.i].error=make_error(ErrorCode::PartialTransfer,"read_scatter");}out[x.i].bytes=std::move(b);}}}
  cur=last;
 }
 return out;
 }catch(const std::bad_alloc&){return fail(ErrorCode::OutOfMemory,"read_scatter");}
}
} // namespace tessera
