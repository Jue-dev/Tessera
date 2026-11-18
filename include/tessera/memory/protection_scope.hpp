#pragma once

#include <utility>

#include "tessera/core/assert.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"
#include "tessera/memory/memory_backend.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

// RAII memory protection modifier.
// Call restore() explicitly to inspect restoration errors; otherwise the destructor attempts restoration
// and reports any failure to the process DiagnosticObserver (and asserts in Debug builds).
class [[nodiscard]] ProtectionScope {
public:
    [[nodiscard]] static Result<ProtectionScope> create(const Process& process,
                                                        AddressRange range,
                                                        MemoryProtection new_protection) {
        if (range.empty()) {
            return fail(ErrorCode::InvalidArgument, "ProtectionScope::create", 0, "Empty range");
        }
        auto prev = memory_backend(process).protect(range.begin(), range.size(), new_protection);
        if (!prev) {
            return std::unexpected(prev.error());
        }
        return ProtectionScope(process, range, *prev);
    }

    ProtectionScope(const ProtectionScope&) = delete;
    ProtectionScope& operator=(const ProtectionScope&) = delete;

    ProtectionScope(ProtectionScope&& other) noexcept
        : process_(std::move(other.process_)),
          range_(other.range_),
          previous_(other.previous_),
          active_(std::exchange(other.active_, false)) {}

    ProtectionScope& operator=(ProtectionScope&& other) noexcept {
        if (this != &other) {
            if (active_) {
                (void)restore_internal();
            }
            process_ = std::move(other.process_);
            range_ = other.range_;
            previous_ = other.previous_;
            active_ = std::exchange(other.active_, false);
        }
        return *this;
    }

    ~ProtectionScope() noexcept {
        if (active_) {
            auto st = restore_internal();
            if (!st) {
                diagnostics::notify(process_.observer(),
                                    DiagnosticSeverity::Warning,
                                    "Memory",
                                    "ProtectionScope destructor failed to restore memory protection",
                                    st.error());
                TESSERA_ASSERT_MSG(false, "ProtectionScope failed to restore protection in destructor");
            }
        }
    }

    [[nodiscard]] Status restore() noexcept {
        if (!active_) {
            return ok();
        }
        return restore_internal();
    }

    void release() noexcept { active_ = false; }

    [[nodiscard]] MemoryProtection previous_protection() const noexcept { return previous_; }
    [[nodiscard]] AddressRange range() const noexcept { return range_; }
    [[nodiscard]] bool active() const noexcept { return active_; }

private:
    ProtectionScope(Process process, AddressRange range, MemoryProtection previous) noexcept
        : process_(std::move(process)),
          range_(range),
          previous_(previous),
          active_(true) {}

    [[nodiscard]] Status restore_internal() noexcept {
        active_ = false;
        auto res = memory_backend(process_).protect(range_.begin(), range_.size(), previous_);
        if (!res) {
            return fail(ErrorCode::ProtectionRestoreFailed,
                        res.error().operation,
                        res.error().native,
                        res.error().detail);
        }
        return ok();
    }

    Process process_;
    AddressRange range_{};
    MemoryProtection previous_ = MemoryProtection::None;
    bool active_ = false;
};

} // namespace tessera
