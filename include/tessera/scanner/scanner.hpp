#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stop_token>
#include <span>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"
#include "tessera/memory/memory_region.hpp"
#include "tessera/pattern/pattern.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

class AddressCursor;

struct ScanProgress {
    std::uint64_t bytes_scanned = 0;
    std::uint64_t total_bytes = 0;
    std::size_t hits_found = 0;
};

enum class ScanReadPolicy : std::uint8_t {
    BestEffort,
    Strict,
};

struct ScanOptions {
    std::size_t max_results = 0; // 0 = unlimited
    std::size_t alignment = 1;
    RegionFilter filter{};
    std::size_t chunk_size = std::size_t{1} << 20; // 1 MiB default
    std::stop_token stop{};
    mutable std::move_only_function<void(const ScanProgress&)> on_progress{};
    DiagnosticObserver* observer = nullptr;
};

struct ScanStats {
    std::uint64_t bytes_scanned = 0;
    std::size_t regions_scanned = 0;
    std::size_t regions_skipped = 0;
    std::size_t read_errors = 0;
};

struct ScanResult {
    std::vector<Address> hits{};
    ScanStats stats{};
    bool truncated = false;
    bool cancelled = false;
};

// Caller-owned scratch storage. Reusing one workspace across scans retains
// the chunk buffer allocation; a workspace must not be shared concurrently.
class ScanWorkspace {
public:
    void reserve(std::size_t bytes) { buffer_.reserve(bytes); }
    [[nodiscard]] std::size_t capacity() const noexcept { return buffer_.capacity(); }

private:
    std::vector<std::byte> buffer_{};
    friend class Scanner;
};

// Thread-safety: const member functions are re-entrant when each concurrent
// scan has independent optional workspace storage.
class Scanner {
public:
    explicit Scanner(Process process) noexcept : process_(std::move(process)) {}

    [[nodiscard]] const Process& process() const noexcept { return process_; }

    [[nodiscard]] Result<ScanResult> scan(AddressRange range,
                                          const Pattern& pattern,
                                          const ScanOptions& options = {}) const;
    [[nodiscard]] Result<ScanResult> scan(AddressRange range,
                                          const Pattern& pattern,
                                          const ScanOptions& options,
                                          ScanReadPolicy read_policy) const;
    [[nodiscard]] Result<ScanResult> scan(AddressRange range,
                                          const Pattern& pattern,
                                          const ScanOptions& options,
                                          ScanWorkspace& workspace,
                                          ScanReadPolicy read_policy = ScanReadPolicy::BestEffort) const;
    [[nodiscard]] Result<ScanResult> scan_streaming(
        AddressRange range,
        const Pattern& pattern,
        const ScanOptions& options,
        FunctionRef<bool(Address)> on_match,
        ScanWorkspace* workspace = nullptr,
        ScanReadPolicy read_policy = ScanReadPolicy::BestEffort) const;

    // Scans several signatures over each memory chunk after a single remote read.
    // The result vector preserves the input pattern order and each pattern has
    // its own max_results quota.
    [[nodiscard]] Result<std::vector<ScanResult>> scan_batch(
        AddressRange range,
        std::span<const Pattern> patterns,
        const ScanOptions& options = {}) const;
    [[nodiscard]] Result<std::vector<ScanResult>> scan_batch(
        AddressRange range,
        std::span<const Pattern> patterns,
        const ScanOptions& options,
        ScanWorkspace& workspace) const;

    [[nodiscard]] Result<Address> find_first(AddressRange range,
                                             const Pattern& pattern,
                                             const ScanOptions& options = {}) const;

    [[nodiscard]] Result<Address> find_unique(AddressRange range,
                                              const Pattern& pattern,
                                              const ScanOptions& options = {}) const;

    // Defined in tessera/resolver/address_cursor.hpp
    [[nodiscard]] AddressCursor find_first_cursor(AddressRange range,
                                                  const Pattern& pattern,
                                                  const ScanOptions& options = {}) const;

    [[nodiscard]] AddressCursor find_unique_cursor(AddressRange range,
                                                   const Pattern& pattern,
                                                   const ScanOptions& options = {}) const;

private:
    [[nodiscard]] Result<ScanResult> scan_impl(
        AddressRange range,
        const Pattern& pattern,
        const ScanOptions& options,
        ScanReadPolicy read_policy,
        ScanWorkspace* workspace,
        FunctionRef<bool(Address)> on_match) const;
    [[nodiscard]] Result<std::vector<ScanResult>> scan_batch_impl(
        AddressRange range,
        std::span<const Pattern> patterns,
        const ScanOptions& options,
        ScanWorkspace* workspace) const;

    Process process_;
};

} // namespace tessera
