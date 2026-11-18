#pragma once

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/memory_backend.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

template <class T>
concept TriviallyReadable = std::is_trivially_copyable_v<T> && std::is_object_v<T> &&
                            !std::is_array_v<T> && std::same_as<T, std::remove_cv_t<T>>;

struct ReadLimits {
    std::size_t max_bytes = 64ULL * 1024ULL * 1024ULL; // 64 MiB default upper bound
};

// Thread-safety: const member functions are re-entrant.
class MemoryReader {
public:
    explicit MemoryReader(Process process) noexcept : process_(std::move(process)) {}

    [[nodiscard]] const Process& process() const noexcept { return process_; }

    [[nodiscard]] Status read_exact(Address address, std::span<std::byte> buffer) const noexcept;

    [[nodiscard]] Result<std::size_t> read_partial(Address address,
                                                   std::span<std::byte> buffer) const noexcept;

    [[nodiscard]] Result<std::vector<std::byte>> read_bytes(Address address,
                                                            std::size_t count,
                                                            ReadLimits limits = {}) const;

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read(Address address) const noexcept {
        std::array<std::byte, sizeof(T)> raw{};
        auto st = read_exact(address, raw);
        if (!st) {
            return std::unexpected(st.error());
        }
        return std::bit_cast<T>(raw);
    }

    [[nodiscard]] Result<Address> read_pointer(Address address) const noexcept;

    [[nodiscard]] Result<std::string> read_cstring(Address address,
                                                   std::size_t max_chars = 256) const;

    [[nodiscard]] Result<std::u16string> read_utf16(Address address,
                                                    std::size_t max_chars = 256) const;

    [[nodiscard]] Result<MemoryRegionInfo> query(Address address) const noexcept;

    [[nodiscard]] Result<bool> is_readable(AddressRange range) const noexcept;
    [[nodiscard]] Result<bool> is_writable(AddressRange range) const noexcept;
    [[nodiscard]] Result<bool> is_executable(AddressRange range) const noexcept;

private:
    Process process_;
};

} // namespace tessera
