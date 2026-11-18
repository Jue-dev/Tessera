#include "tessera/core/core.hpp"

namespace tessera {

static_assert(sizeof(Address) == sizeof(std::uint64_t));
static_assert(std::is_trivially_copyable_v<Address>);
static_assert(sizeof(Rva) == sizeof(std::uint32_t));
static_assert(std::is_trivially_copyable_v<Rva>);
static_assert(sizeof(ProcessId) == sizeof(std::uint32_t));
static_assert(std::is_trivially_copyable_v<ProcessId>);

} // namespace tessera
