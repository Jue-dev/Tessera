#pragma once

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/module/module.hpp"
#include "tessera/module/pe_image.hpp"
#include "tessera/process/process.hpp"
#include "tessera/targets/target_profile.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace tessera::targets {

enum class FingerprintPolicy : std::uint8_t {
    Strict,
    Performance,
};

enum class CheckStatus : std::uint8_t {
    Passed,
    Failed,
    Skipped,
    NotApplicable,
};

struct ValidationCheckResult {
    ValidationRuleKind rule = ValidationRuleKind::ModuleRange;
    CheckStatus status = CheckStatus::Skipped;
    bool required = true;
    std::string reason{};
};

struct ValidationReport {
    std::vector<ValidationCheckResult> checks{};
    bool all_required_passed = false;
    bool has_independent_check = false;
};

enum class ResolutionStatus : std::uint8_t {
    VerifiedExactBuild,
    VerifiedCompatibleBuild,
    CandidateFound,
    NeedsReview,
    Ambiguous,
    Stale,
    NotFound,
    IncompatibleTarget,
};

class AddressResolver;

// Session-scoped verified address token.
// Can ONLY be constructed by AddressResolver when all required validation checks succeed.
class [[nodiscard]] VerifiedAddress {
public:
    [[nodiscard]] Address address() const noexcept { return address_; }
    [[nodiscard]] Rva rva() const noexcept { return rva_; }
    [[nodiscard]] std::string_view entry_id() const noexcept { return entry_id_; }
    [[nodiscard]] std::string_view module_id() const noexcept { return module_id_; }
    [[nodiscard]] ResolutionStatus status() const noexcept { return status_; }

private:
    friend class AddressResolver;

    VerifiedAddress(Address address, Rva rva, std::string entry_id, std::string module_id,
                    ResolutionStatus status) noexcept
        : address_(address), rva_(rva), entry_id_(std::move(entry_id)), module_id_(std::move(module_id)),
          status_(status) {}

    Address address_{};
    Rva rva_{};
    std::string entry_id_{};
    std::string module_id_{};
    ResolutionStatus status_ = ResolutionStatus::VerifiedExactBuild;
};

struct ResolutionOutcome {
    ResolutionStatus status = ResolutionStatus::NotFound;
    ValidationReport report{};
    std::optional<Address> candidate_address{};
    std::optional<Rva> candidate_rva{};
    bool from_session_cache = false;

    [[nodiscard]] const std::optional<VerifiedAddress>& verified() const noexcept { return verified_; }

private:
    friend class AddressResolver;
    std::optional<VerifiedAddress> verified_{};
};

struct ResolutionTraceStep {
    std::string stage{};
    ResolutionStatus status = ResolutionStatus::NotFound;
    std::string detail{};
};

struct ResolutionTrace {
    std::vector<ResolutionTraceStep> steps{};
};

// Describes a loaded module inside a target session (supports both OS modules and synthetic test modules).
struct TargetModuleContext {
    std::string module_id = "main";
    std::string file_name{};
    AddressRange range{};
    ModuleFingerprint fingerprint{};
    std::optional<PeImage> pe_image{};
    std::vector<Section> custom_sections{};
};

class TargetFingerprinter {
public:
    explicit TargetFingerprinter(FingerprintPolicy policy = FingerprintPolicy::Strict) noexcept
        : policy_(policy) {}

    [[nodiscard]] Result<ModuleFingerprint> fingerprint_file(std::string module_id,
                                                             const std::filesystem::path& file_path);

    [[nodiscard]] Result<ModuleFingerprint> fingerprint_memory_module(const Process& process,
                                                                      std::string module_id,
                                                                      std::string file_name,
                                                                      AddressRange module_range);

    void clear_cache() noexcept;

private:
    struct CacheEntry {
        std::filesystem::path path{};
        std::uintmax_t file_size = 0;
        std::filesystem::file_time_type last_write_time{};
        ModuleFingerprint fingerprint{};
    };

    FingerprintPolicy policy_ = FingerprintPolicy::Strict;
    mutable std::mutex mutex_{};
    std::vector<CacheEntry> cache_{};
};

// Resolves and validates addresses against a TargetProfile with session caching and build persistence rules.
class AddressResolver {
public:
    explicit AddressResolver(Process process, std::vector<TargetModuleContext> modules = {}) noexcept
        : process_(std::move(process)), modules_(std::move(modules)) {}

    void set_modules(std::vector<TargetModuleContext> modules);
    [[nodiscard]] std::span<const TargetModuleContext> modules() const noexcept { return modules_; }

    void invalidate_session_cache() noexcept;

    [[nodiscard]] ResolutionOutcome
    resolve_entry(TargetProfile& profile, std::string_view entry_id,
                  PersistPolicy persist_policy = PersistPolicy::AskBeforePersist,
                  TargetProfileStore* store = nullptr);
    [[nodiscard]] ResolutionOutcome resolve_entry(TargetProfile& profile, std::string_view entry_id,
                                                  PersistPolicy persist_policy, TargetProfileStore* store,
                                                  ResolutionTrace* trace);

private:
    struct SessionCacheItem {
        ProcessId pid{};
        std::uint64_t profile_revision = 0;
        std::string entry_id{};
        std::string module_id{};
        Address module_base{};
        std::string module_sha256{};
        VerifiedAddress verified;
        ValidationReport report{};
    };

    [[nodiscard]] const TargetModuleContext* find_loaded_module(std::string_view module_id) const noexcept;

    [[nodiscard]] ValidationReport run_validation_checks(const TargetModuleContext& mod_ctx,
                                                         const AddressEntry& entry, Address candidate,
                                                         bool is_compatible_build) const;

    Process process_;
    std::vector<TargetModuleContext> modules_{};
    std::vector<SessionCacheItem> session_cache_{};
};

struct DiscoveryCandidate {
    std::string entry_id{};
    std::string name{};
    AddressKind kind = AddressKind::Global;
    std::string module_id = "main";
    Address address{};
    ValueDescriptor value{};
    std::string fallback_pattern{};
    std::int64_t fallback_result_offset = 0;
    std::size_t expected_bytes_len = 8;
};

class DiscoverySession {
public:
    DiscoverySession(Process process, const TargetModuleContext& mod_ctx) noexcept
        : process_(std::move(process)), mod_ctx_(mod_ctx) {}

    [[nodiscard]] Result<AddressEntry> capture_and_verify(TargetProfile& profile,
                                                          const DiscoveryCandidate& candidate) const;

private:
    Process process_;
    const TargetModuleContext& mod_ctx_;
};

} // namespace tessera::targets
