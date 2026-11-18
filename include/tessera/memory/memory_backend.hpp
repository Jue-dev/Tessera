#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/memory_region.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

class IMemoryBackend {
public:
    virtual ~IMemoryBackend() = default;

    // Reads up to buffer.size() bytes. Returns actual bytes transferred (>0 on partial transfer).
    [[nodiscard]] virtual Result<std::size_t> read(Address address,
                                                   std::span<std::byte> buffer) const = 0;

    // Writes up to data.size() bytes. Returns actual bytes transferred.
    [[nodiscard]] virtual Result<std::size_t> write(Address address,
                                                    std::span<const std::byte> data) const = 0;

    [[nodiscard]] virtual Result<MemoryRegionInfo> query(Address address) const = 0;

    [[nodiscard]] virtual Result<MemoryProtection> protect(Address address,
                                                           std::uint64_t size,
                                                           MemoryProtection new_protection) const = 0;

    [[nodiscard]] virtual Status flush_instruction_cache(AddressRange range) const = 0;
};

[[nodiscard]] const IMemoryBackend& memory_backend(const Process& process) noexcept;

} // namespace tessera
