#include "tessera/patch/patch.hpp"

#include <new>

#include "tessera/core/assert.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/memory_writer.hpp"

namespace tessera {

Patch::Patch(ProcessAddress target, std::vector<std::byte> bytes, PatchOptions options) noexcept
    : target_(std::move(target)),
      new_bytes_(std::move(bytes)),
      options_(std::move(options)),
      state_(PatchState::Created) {}

Patch::Patch(Patch&& other) noexcept
    : target_(std::move(other.target_)),
      new_bytes_(std::move(other.new_bytes_)),
      original_bytes_(std::move(other.original_bytes_)),
      pending_protection_report_(std::move(other.pending_protection_report_)),
      options_(std::move(other.options_)),
      state_(std::exchange(other.state_, PatchState::Created)) {
    other.options_.auto_restore = false;
    other.pending_protection_report_.reset();
}

Patch& Patch::operator=(Patch&& other) noexcept {
    if (this != &other) {
        auto restore_status = finish_in_destructor();
        if (!restore_status) {
            // Do not discard an applied patch whose automatic restoration failed.
            return *this;
        }
        target_ = std::move(other.target_);
        new_bytes_ = std::move(other.new_bytes_);
        original_bytes_ = std::move(other.original_bytes_);
        pending_protection_report_ = std::move(other.pending_protection_report_);
        options_ = std::move(other.options_);
        state_ = std::exchange(other.state_, PatchState::Created);
        other.options_.auto_restore = false;
        other.pending_protection_report_.reset();
    }
    return *this;
}

Patch::~Patch() noexcept {
    // The helper reports restoration failures through the diagnostic observer.
    // Its Status is intentionally not propagated from a noexcept destructor.
    (void)finish_in_destructor();
}

Status Patch::finish_in_destructor() noexcept {
    if (pending_protection_report_.has_value()) {
        MemoryWriter writer{target_.process()};
        auto protection_status =
            writer.restore_pending_protections(*pending_protection_report_);
        if (!protection_status) {
            diagnostics::notify(target_.process().observer(),
                                DiagnosticSeverity::Warning,
                                "Patch",
                                "Pending page-protection restoration failed during Patch cleanup; retry ownership will be released with the Patch",
                                protection_status.error());
            return protection_status;
        }
        pending_protection_report_.reset();
    }
    if (options_.auto_restore && state_ == PatchState::Applied) {
        auto st = restore();
        if (!st) {
            diagnostics::notify(target_.process().observer(),
                                DiagnosticSeverity::Warning,
                                "Patch",
                                "Auto-restore failed in Patch destructor",
                                st.error());
            return st;
        }
    }
    return ok();
}

Result<Patch> Patch::create(ProcessAddress target,
                            std::vector<std::byte> bytes,
                            PatchOptions options) {
    if (target.is_null()) {
        return fail(ErrorCode::NullAddress, "Patch::create");
    }
    if (bytes.empty()) {
        return fail(ErrorCode::InvalidArgument, "Patch::create", 0, "Patch byte vector is empty");
    }
    if (options.expected_original.has_value()) {
        if (options.expected_original->pattern.empty() ||
            options.expected_original->pattern.size() != bytes.size()) {
            return fail(ErrorCode::InvalidArgument,
                        "Patch::create",
                        0,
                        "expected_original size must match patch byte length");
        }
    }
    return Patch{std::move(target), std::move(bytes), std::move(options)};
}

Result<Patch> Patch::nop(ProcessAddress target, std::size_t count, PatchOptions options) {
    if (count == 0) {
        return fail(ErrorCode::InvalidArgument, "Patch::nop", 0, "NOP count must be > 0");
    }
    try {
        std::vector<std::byte> nops(count, std::byte{0x90});
        return create(std::move(target), std::move(nops), std::move(options));
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Patch::nop");
    }
}

Status Patch::apply() {
    if (state_ == PatchState::Applied) {
        return ok();
    }
    if (state_ == PatchState::Indeterminate) {
        return fail(ErrorCode::Conflict,
                    "Patch::apply",
                    0,
                    "Patch is in an indeterminate state after a previous failed rollback");
    }

    MemoryReader reader{target_.process()};
    auto current_bytes = reader.read_bytes(target_.address(), new_bytes_.size());
    if (!current_bytes) {
        return std::unexpected(current_bytes.error());
    }

    if (options_.expected_original.has_value()) {
        if (!options_.expected_original->pattern.matches(*current_bytes)) {
            return fail(ErrorCode::ValidationFailed,
                        "Patch::apply",
                        0,
                        "Target memory bytes do not match expected_original pattern");
        }
    }

    MemoryWriter writer{target_.process()};
    auto report = writer.write_with_report(target_.address(), new_bytes_);
    if (!report) {
        return std::unexpected(report.error());
    }
    const auto retain_pending_restore = [&]() {
        if (!report->pending_protection_restores.empty()) {
            pending_protection_report_ = std::move(*report);
        }
    };
    if (report->write_error.has_value()) {
        const Error error = *report->write_error;
        if (report->bytes_written > 0 &&
            (!report->rolled_back || report->rollback_error.has_value())) {
            state_ = PatchState::Indeterminate;
        }
        retain_pending_restore();
        return std::unexpected(error);
    }
    if (report->rollback_error.has_value()) {
        const Error error = *report->rollback_error;
        state_ = PatchState::Indeterminate;
        retain_pending_restore();
        return std::unexpected(error);
    }

    original_bytes_ = std::move(*current_bytes);
    state_ = PatchState::Applied;
    if (report->protection_restore_warning.has_value()) {
        const Error error = *report->protection_restore_warning;
        retain_pending_restore();
        return std::unexpected(error);
    }
    if (report->icache_flush_error.has_value()) {
        const Error error = *report->icache_flush_error;
        retain_pending_restore();
        return std::unexpected(error);
    }
    retain_pending_restore();
    return ok();
}

Status Patch::restore() noexcept {
    MemoryWriter writer{target_.process()};
    if (pending_protection_report_.has_value()) {
        auto protection_status =
            writer.restore_pending_protections(*pending_protection_report_);
        if (!protection_status) {
            return protection_status;
        }
        pending_protection_report_.reset();
    }
    if (state_ != PatchState::Applied) {
        return state_ == PatchState::Indeterminate
                   ? fail(ErrorCode::Conflict, "Patch::restore", 0, "Patch state is Indeterminate")
                   : ok();
    }

    MemoryReader reader{target_.process()};
    auto current_bytes = reader.read_bytes(target_.address(), new_bytes_.size());
    if (!current_bytes) {
        return std::unexpected(current_bytes.error());
    }
    if (*current_bytes != new_bytes_) {
        return fail(ErrorCode::Conflict,
                    "Patch::restore",
                    0,
                    "Target bytes no longer match this patch; refusing to overwrite another writer");
    }

    auto report = writer.write_with_report(target_.address(), original_bytes_);
    if (!report) {
        return std::unexpected(report.error());
    }
    const auto retain_pending_restore = [&]() {
        if (!report->pending_protection_restores.empty()) {
            pending_protection_report_ = std::move(*report);
        }
    };
    if (report->write_error.has_value()) {
        const Error error = *report->write_error;
        if (report->bytes_written > 0 &&
            (!report->rolled_back || report->rollback_error.has_value())) {
            state_ = PatchState::Indeterminate;
        }
        retain_pending_restore();
        return std::unexpected(error);
    }
    if (report->rollback_error.has_value()) {
        const Error error = *report->rollback_error;
        state_ = PatchState::Indeterminate;
        retain_pending_restore();
        return std::unexpected(error);
    }

    state_ = PatchState::Restored;
    if (report->protection_restore_warning.has_value()) {
        const Error error = *report->protection_restore_warning;
        retain_pending_restore();
        return std::unexpected(error);
    }
    if (report->icache_flush_error.has_value()) {
        const Error error = *report->icache_flush_error;
        retain_pending_restore();
        return std::unexpected(error);
    }
    retain_pending_restore();
    return ok();
}

void PatchTransaction::add(Patch patch) {
    patches_.push_back(std::move(patch));
}

TransactionReport PatchTransaction::apply() {
    TransactionReport report{};
    report.steps.resize(patches_.size());
    std::vector<std::size_t> newly_applied;
    newly_applied.reserve(patches_.size());
    for (std::size_t i = 0; i < patches_.size(); ++i) {
        report.steps[i].index = i;
        report.steps[i].state = patches_[i].state();
    }

    std::size_t failed_index = patches_.size();
    for (std::size_t i = 0; i < patches_.size(); ++i) {
        const PatchState before = patches_[i].state();
        auto st = patches_[i].apply();
        report.steps[i].state = patches_[i].state();
        if (before != PatchState::Applied && patches_[i].state() == PatchState::Applied) {
            // Include a patch that wrote bytes but returned a safety warning so
            // the transaction can still roll it back.
            newly_applied.push_back(i);
        }
        if (!st) {
            report.steps[i].error = st.error();
            report.failure_error = st.error();
            failed_index = i;
            break;
        }
        ++report.applied_count;
    }

    if (failed_index == patches_.size()) {
        report.succeeded = true;
        return report;
    }

    // Roll back only patches newly applied by this invocation. Previously
    // applied patches are caller-owned state and must not be undone.
    if (!newly_applied.empty()) {
        bool rollback_complete = true;
        report.rolled_back = true;
        for (auto it = newly_applied.rbegin(); it != newly_applied.rend(); ++it) {
            const std::size_t idx = *it;
            auto rst = patches_[idx].restore();
            report.steps[idx].state = patches_[idx].state();
            report.steps[idx].rolled_back = rst.has_value();
            if (!rst) {
                rollback_complete = false;
                report.steps[idx].rollback_error = rst.error();
            }
        }
        report.rolled_back = rollback_complete;
    }

    return report;
}

Status PatchTransaction::restore_all() noexcept {
    Status first_err = ok();
    for (std::size_t rev = patches_.size(); rev > 0; --rev) {
        const std::size_t idx = rev - 1;
        // restore() retries retained protection tickets before inspecting
        // the patch state. This must include Restored patches too: their bytes
        // may have been restored successfully while the protection retry failed.
        auto st = patches_[idx].restore();
        if (!st && first_err) {
            first_err = st;
        }
    }
    return first_err;
}

} // namespace tessera
