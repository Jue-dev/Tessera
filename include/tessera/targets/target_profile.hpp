#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"

namespace tessera::targets {

enum class TargetArch : std::uint8_t {
    X86,
    X64,
};

enum class AddressKind : std::uint8_t {
    Function,
    Global,
    Object,
    Field,
    VTable,
    Pointer,
    Data,
    Export,
};

enum class ValueType : std::uint8_t {
    UInt8,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Pointer,
    Bytes,
};

struct ValueDescriptor {
    ValueType type = ValueType::UInt32;
    std::uint32_t size = 4;
};

enum class ResolutionStrategy : std::uint8_t {
    Rva,
    Export,
    Pattern,
    PointerChain,
    Relative,
    Field,
    RttiVTable,
    StringXref,
    PythonMethod,
};

struct ResolutionRecipe {
    ResolutionStrategy strategy = ResolutionStrategy::Rva;
    Rva rva{};
    std::string export_name{};
    std::uint16_t export_ordinal = 0;
    std::string pattern{};
    std::string section{};
    std::size_t match_count = 1;
    std::int64_t result_offset = 0;
    std::vector<std::int64_t> pointer_offsets{};
    std::size_t rel_disp_offset = 3;
    std::size_t rel_instr_len = 7;
    std::string class_name{};
    std::optional<std::size_t> vtable_index{};
    std::string string_literal{};
    std::string python_method{};
};

enum class ValidationRuleKind : std::uint8_t {
    ModuleRange,
    Section,
    MemoryReadable,
    MemoryWritable,
    MemoryExecutable,
    ExpectedBytes,
    SecondarySignature,
    PointerSanity,
    ValueRange,
    InstructionShape,
};

struct ValidationRule {
    ValidationRuleKind kind = ValidationRuleKind::ModuleRange;
    bool required = true;
    std::string value{};              // section name, pattern text, etc.
    std::int64_t relative_offset = 0; // offset for SecondarySignature
    std::int64_t min_value = 0;
    std::int64_t max_value = 0;
};

struct ValidationPolicy {
    std::vector<ValidationRule> rules{};
    std::size_t minimum_unique_candidates = 1;
    bool allow_compatible_build = true;
};

[[nodiscard]] ValidationPolicy default_validation_policy_for(AddressKind kind);

struct ModuleFingerprint {
    std::string module_id{};
    std::string file_name{};
    TargetArch architecture = TargetArch::X64;
    std::uint32_t size_of_image = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t checksum = 0;
    std::string codeview_guid{};
    std::uint32_t codeview_age = 0;
    std::string sha256{};
    bool from_metadata_cache = false;

    [[nodiscard]] bool matches_strong(const ModuleFingerprint& other) const noexcept;
    [[nodiscard]] bool matches_fast(const ModuleFingerprint& other) const noexcept;
};

struct BuildFingerprint {
    std::string file_version{};
    std::uint32_t size_of_image = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t checksum = 0;
    std::string codeview_guid{};
    std::uint32_t codeview_age = 0;
    std::string sha256{};

    [[nodiscard]] bool matches(const BuildFingerprint& other) const noexcept;
};

struct AuditRecord {
    std::string timestamp_utc{};
    std::string source_build_id{};
    std::string strategy_used{};
    std::string summary{};
};

struct AddressEntry {
    std::string id{};
    std::string name{};
    std::string description{};
    std::string category{};
    AddressKind kind = AddressKind::Global;
    std::string module_id = "main";
    ValueDescriptor value{};
    ResolutionRecipe primary{};
    std::optional<ResolutionRecipe> fallback{};
    ValidationPolicy validation{};
    std::vector<std::string> tags{};
    std::optional<AuditRecord> audit{};
};

struct TargetBuild {
    std::string build_id{};
    TargetArch architecture = TargetArch::X64;
    BuildFingerprint fingerprint{};
    std::vector<ModuleFingerprint> modules{};
    std::vector<AddressEntry> addresses{};

    [[nodiscard]] const ModuleFingerprint* find_module(std::string_view module_id) const noexcept;
    [[nodiscard]] const AddressEntry* find_address(std::string_view entry_id) const noexcept;
    [[nodiscard]] AddressEntry* find_address(std::string_view entry_id) noexcept;
};

struct TargetIdentity {
    std::string application_id{};
    std::string display_name{};
    std::string publisher{};
    std::vector<std::string> executables{};
    std::vector<TargetArch> supported_architectures{TargetArch::X86, TargetArch::X64};
};

struct TargetProfile {
    std::uint32_t format_version = 1;
    std::uint32_t profile_version = 1;
    std::uint64_t revision = 1;
    TargetIdentity application{};
    std::vector<TargetBuild> builds{};

    [[nodiscard]] const TargetBuild* find_build(std::string_view build_id) const noexcept;
    [[nodiscard]] TargetBuild* find_build(std::string_view build_id) noexcept;
};

// Validates structural integrity and safety rules of a TargetProfile (independent of Process/Memory).
[[nodiscard]] Status validate_target_profile_schema(const TargetProfile& profile);

enum class PersistPolicy : std::uint8_t {
    ReadOnly,
    AskBeforePersist,
    AutoPersistVerified,
};

class TargetProfileStore {
public:
    virtual ~TargetProfileStore() = default;
    [[nodiscard]] virtual Result<TargetProfile> load(std::string_view application_id) const = 0;
    [[nodiscard]] virtual Status save(TargetProfile& profile) = 0;
    [[nodiscard]] virtual Result<std::vector<std::string>> list() const = 0;
};

} // namespace tessera::targets
