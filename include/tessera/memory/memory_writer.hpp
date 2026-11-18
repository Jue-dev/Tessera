#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <optional>
#include <span>

#include "tessera/core/error.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

struct WriteOptions {
    bool rollback_on_failure = true;
    bool flush_icache = true;
};

struct WriteReport {
    std::size_t bytes_written = 0;
    std::size_t regions_touched = 0;
    bool rolled_back = false;
    std::optional<Error> rollback_error{};
    std::optional<Error> protection_restore_warning{};
    std::optional<Error> write_error{};

    [[nodiscard]] constexpr bool succeeded() const noexcept {
        return !write_error.has_value();
    }
};

// Thread-safety: const member functions are re-entrant.
class MemoryWriter {
public:
    explicit MemoryWriter(Process process) noexcept : process_(std::move(process)) {}

    [[nodiscard]] const Process& process() const noexcept { return process_; }

    // Performs 2-pass validated write across regions, restoring page protection and optionally
    // rolling back previously written bytes on mid-transfer failure.
    // Returns WriteReport even when a mid-transfer failure occurs so partial state is inspectable;
    // returns unexpected(Error) if validation fails before any byte is touched.
    [[nodiscard]] Result<WriteReport> write_with_report(Address address,
                                                        std::span<const std::byte> data,
                                                        WriteOptions options = {}) const;

    [[nodiscard]] Status write(Address address,
                               std::span<const std::byte> data,
                               WriteOptions options = {}) const;

    template <TriviallyReadable T>
    [[nodiscard]] Status write_value(Address address,
                                     const T& value,
                                     WriteOptions options = {}) const {
        const auto bytes = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
        return write(address, bytes, options);
    }

    [[nodiscard]] Status fill(Address address,
                              std::byte value,
                              std::size_t count,
                              WriteOptions options = {}) const;

    [[nodiscard]] Status nop(Address address,
                             std::size_t count,
                             WriteOptions options = {}) const {
        return fill(address, std::byte{0x90}, count, options);
    }

private:
    Process process_;
};

} // namespace tessera
