#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

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

struct PendingProtectionRestore {
    AddressRange range{};
    MemoryProtection original_protection = MemoryProtection::None;
};

struct WriteReport {
    // A failed restore remains explicitly owned by this report. Call
    // MemoryWriter::restore_pending_protections(report) to retry it.
    std::vector<PendingProtectionRestore> pending_protection_restores{};
    std::size_t bytes_written = 0;
    std::size_t regions_touched = 0;
    bool rolled_back = false;
    std::optional<Error> rollback_error{};
    std::optional<Error> protection_restore_warning{};
    std::optional<Error> icache_flush_error{};
    std::optional<Error> write_error{};

    [[nodiscard]] constexpr bool succeeded() const noexcept {
        return pending_protection_restores.empty() &&
               !write_error.has_value() &&
               !rollback_error.has_value() &&
               !protection_restore_warning.has_value() &&
               !icache_flush_error.has_value();
    }
};

// Thread-safety: const member functions are re-entrant.
class MemoryWriter {
public:
    explicit MemoryWriter(Process process) noexcept : process_(std::move(process)) {}

    [[nodiscard]] const Process& process() const noexcept { return process_; }

    // Performs 2-pass validated write across regions, restoring page protection and optionally
    // rolling back previously written bytes on mid-transfer failure.
    // Returns WriteReport even when a mid-transfer or safety failure occurs so partial state is inspectable.
    // Retain the report when protection restoration fails and retry it with
    // restore_pending_protections(). The status-only write() convenience API
    // performs one automatic retry but cannot expose persistent retry tickets.
    [[nodiscard]] Result<WriteReport> write_with_report(Address address,
                                                        std::span<const std::byte> data,
                                                        WriteOptions options = {}) const;

    // Retries every outstanding page-protection restoration recorded by a prior
    // write_with_report call. Failed entries remain in the report for another retry.
    [[nodiscard]] Status restore_pending_protections(WriteReport& report) const;

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
