#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "tessera/core/error.hpp"
#include "tessera/core/result.hpp"
#include "tessera/memory/process_address.hpp"
#include "tessera/memory/memory_writer.hpp"
#include "tessera/pattern/pattern.hpp"

namespace tessera {

struct ExpectedBytes {
    Pattern pattern{};

    ExpectedBytes() = default;
    explicit ExpectedBytes(Pattern pat) noexcept : pattern(std::move(pat)) {}

    [[nodiscard]] static Result<ExpectedBytes> from_bytes(std::span<const std::byte> raw) {
        auto pat = Pattern::from_bytes(raw);
        if (!pat) {
            return std::unexpected(pat.error());
        }
        return ExpectedBytes{std::move(*pat)};
    }
};

struct PatchOptions {
    bool auto_restore = false;
    std::optional<ExpectedBytes> expected_original{};
};

enum class PatchState : std::uint8_t {
    Created,
    Applied,
    Restored,
    Indeterminate,
};

// Move-only byte patch with original-byte verification, backup, and optional RAII restoration.
// Outstanding page-protection restoration reports remain owned by the Patch until retried.
class [[nodiscard]] Patch {
public:
    [[nodiscard]] static Result<Patch> create(ProcessAddress target,
                                              std::vector<std::byte> bytes,
                                              PatchOptions options = {});

    [[nodiscard]] static Result<Patch> nop(ProcessAddress target,
                                           std::size_t count,
                                           PatchOptions options = {});

    Patch(const Patch&) = delete;
    Patch& operator=(const Patch&) = delete;

    Patch(Patch&& other) noexcept;
    Patch& operator=(Patch&& other) noexcept;

    ~Patch() noexcept;

    [[nodiscard]] Status apply();
    [[nodiscard]] Status restore() noexcept;

    [[nodiscard]] PatchState state() const noexcept { return state_; }
    [[nodiscard]] const ProcessAddress& target() const noexcept { return target_; }
    [[nodiscard]] std::span<const std::byte> original() const noexcept { return original_bytes_; }
    [[nodiscard]] std::span<const std::byte> patch_bytes() const noexcept { return new_bytes_; }

    void disarm_auto_restore() noexcept { options_.auto_restore = false; }

private:
    Patch(ProcessAddress target, std::vector<std::byte> bytes, PatchOptions options) noexcept;
    [[nodiscard]] Status finish_in_destructor() noexcept;

    ProcessAddress target_;
    std::vector<std::byte> new_bytes_{};
    std::vector<std::byte> original_bytes_{};
    std::optional<WriteReport> pending_protection_report_{};
    PatchOptions options_{};
    PatchState state_ = PatchState::Created;
};

struct PatchStepStatus {
    std::size_t index = 0;
    PatchState state = PatchState::Created;
    std::optional<Error> error{};
    bool rolled_back = false;
    std::optional<Error> rollback_error{};
};

struct TransactionReport {
    bool succeeded = false;
    std::size_t applied_count = 0;
    bool rolled_back = false;
    std::optional<Error> failure_error{};
    std::vector<PatchStepStatus> steps{};
};

class PatchTransaction {
public:
    PatchTransaction() = default;

    void add(Patch patch);

    // Applies all patches in order. If any patch fails, previously applied patches in this
    // transaction are restored in reverse order.
    [[nodiscard]] TransactionReport apply();

    // Restores applied patches and retries every retained protection ticket,
    // including tickets left by failed applies or by protection failures after
    // bytes have already been restored.
    [[nodiscard]] Status restore_all() noexcept;

    [[nodiscard]] std::span<const Patch> patches() const noexcept { return patches_; }

private:
    std::vector<Patch> patches_{};
};

} // namespace tessera
