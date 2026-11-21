#include "tessera/memory/memory_snapshot.hpp"
#include <new>
#include "tessera/memory/memory_reader.hpp"
namespace tessera {
Result<MemorySnapshot> MemorySnapshot::capture(const Process&p,AddressRange r){if(r.empty()||r.size()>static_cast<uint64_t>((std::numeric_limits<size_t>::max)()))return fail(ErrorCode::InvalidArgument,"MemorySnapshot::capture");MemoryReader reader{p};auto b=reader.read_bytes(r.begin(),static_cast<size_t>(r.size()));if(!b)return std::unexpected(b.error());return MemorySnapshot{r.begin(),std::move(*b)};}
Result<std::vector<ChangedRange>> diff(const MemorySnapshot&a,const MemorySnapshot&b){if(a.base!=b.base||a.bytes.size()!=b.bytes.size())return fail(ErrorCode::InvalidArgument,"MemorySnapshot::diff");try{std::vector<ChangedRange> out;size_t i=0;while(i<a.bytes.size()){if(a.bytes[i]==b.bytes[i]){++i;continue;}size_t s=i;while(i<a.bytes.size()&&a.bytes[i]!=b.bytes[i])++i;ChangedRange r{};r.offset=s;r.old_bytes.assign(a.bytes.begin()+static_cast<ptrdiff_t>(s),a.bytes.begin()+static_cast<ptrdiff_t>(i));r.new_bytes.assign(b.bytes.begin()+static_cast<ptrdiff_t>(s),b.bytes.begin()+static_cast<ptrdiff_t>(i));out.push_back(std::move(r));}return out;}catch(const std::bad_alloc&){return fail(ErrorCode::OutOfMemory,"MemorySnapshot::diff");}}
} // namespace tessera
