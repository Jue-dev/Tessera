#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/enum_flags.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/process/process.hpp"

namespace tessera {

enum class PeKind : std::uint8_t {
    Pe32,
    Pe32Plus,
};

enum class SectionCharacteristics : std::uint32_t {
    None = 0,
    Code = 0x00000020u,
    InitializedData = 0x00000040u,
    UninitializedData = 0x00000080u,
    Discardable = 0x02000000u,
    NotCached = 0x04000000u,
    NotPaged = 0x08000000u,
    Shared = 0x10000000u,
    Execute = 0x20000000u,
    Read = 0x40000000u,
    Write = 0x80000000u,
};

} // namespace tessera

TESSERA_ENABLE_ENUM_FLAGS(tessera::SectionCharacteristics);

namespace tessera {

struct Section {
    std::string name{};
    Rva rva{};
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    SectionCharacteristics characteristics = SectionCharacteristics::None;
    Address module_base{};

    [[nodiscard]] constexpr std::uint32_t effective_size() const noexcept {
        return virtual_size != 0 ? virtual_size : raw_size;
    }

    [[nodiscard]] constexpr AddressRange range() const noexcept {
        if (!module_base.is_null()) {
            auto start = module_base.add_rva(rva);
            if (start) {
                return AddressRange{*start, effective_size()};
            }
        }
        return AddressRange{Address{rva.value()}, effective_size()};
    }

    [[nodiscard]] constexpr bool is_executable() const noexcept {
        return has_flag(characteristics, SectionCharacteristics::Execute);
    }

    [[nodiscard]] constexpr bool is_readable() const noexcept {
        return has_flag(characteristics, SectionCharacteristics::Read);
    }

    [[nodiscard]] constexpr bool is_writable() const noexcept {
        return has_flag(characteristics, SectionCharacteristics::Write);
    }
};

struct ExportTarget {
    std::string name{};
    std::uint16_t ordinal = 0;
    Rva rva{};
    Address address{}; // Resolved VA if loaded from memory or base was provided
    std::optional<std::string> forwarder{};

    [[nodiscard]] bool is_forwarded() const noexcept { return forwarder.has_value(); }
};

struct ImportEntry {
    std::string module_name{};
    std::string function_name{};
    std::uint16_t ordinal = 0;
    Rva iat_rva{};
    bool by_ordinal = false;
};

struct PeFunctionEntry {
    Rva begin_rva{};
    Rva end_rva{};
    Rva unwind_info_rva{};

    [[nodiscard]] constexpr std::uint32_t size() const noexcept {
        return end_rva.value() > begin_rva.value() ? (end_rva.value() - begin_rva.value()) : 0u;
    }
};

struct BaseRelocation {
    Rva location{};
    std::uint8_t type = 0;
};

struct CodeViewInfo {
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t age = 0;
    std::string pdb_path{};

    [[nodiscard]] std::string guid_string() const;
};

// Bounds-checked Portable Executable (PE32 and PE32+) parser supporting both mapped memory
// images and raw on-disk files.
class PeImage {
public:
    static constexpr std::size_t kMaxSections = 96;
    static constexpr std::size_t kMaxExports = 65536;
    static constexpr std::size_t kMaxImports = 65536;
    static constexpr std::size_t kMaxExceptionFunctions = 262144;

    [[nodiscard]] static Result<PeImage> from_memory(const Process& process, Address base);

    [[nodiscard]] static Result<PeImage> from_file(const std::filesystem::path& path);

    [[nodiscard]] static Result<PeImage> from_raw_bytes(std::span<const std::byte> file_bytes,
                                                        Address load_base = {});

    [[nodiscard]] PeKind kind() const noexcept { return kind_; }
    [[nodiscard]] std::uint16_t machine() const noexcept { return machine_; }
    [[nodiscard]] std::uint64_t image_base() const noexcept { return image_base_; }
    [[nodiscard]] std::uint32_t size_of_image() const noexcept { return size_of_image_; }
    [[nodiscard]] std::uint32_t timestamp() const noexcept { return timestamp_; }
    [[nodiscard]] std::uint32_t checksum() const noexcept { return checksum_; }
    [[nodiscard]] Rva entry_point() const noexcept { return entry_point_; }
    [[nodiscard]] Address loaded_base() const noexcept { return loaded_base_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept { return sections_; }
    [[nodiscard]] Result<Section> find_section(std::string_view name) const;

    [[nodiscard]] std::span<const ExportTarget> exports() const noexcept { return exports_; }
    [[nodiscard]] Result<ExportTarget> find_export(std::string_view name) const;
    [[nodiscard]] Result<ExportTarget> find_export(std::uint16_t ordinal) const;

    [[nodiscard]] std::span<const ImportEntry> imports() const noexcept { return imports_; }
    [[nodiscard]] Result<ImportEntry> find_import(std::string_view module_name,
                                                  std::string_view function_name) const;

    [[nodiscard]] std::span<const PeFunctionEntry> exception_functions() const noexcept {
        return exception_functions_;
    }

    [[nodiscard]] std::span<const BaseRelocation> relocations() const noexcept {
        return relocations_;
    }

    [[nodiscard]] const std::optional<CodeViewInfo>& code_view() const noexcept {
        return code_view_;
    }

private:
    PeKind kind_ = PeKind::Pe32Plus;
    std::uint16_t machine_ = 0;
    std::uint64_t image_base_ = 0;
    std::uint32_t size_of_image_ = 0;
    std::uint32_t timestamp_ = 0;
    std::uint32_t checksum_ = 0;
    Rva entry_point_{};
    Address loaded_base_{};
    std::vector<Section> sections_{};
    std::vector<ExportTarget> exports_{};
    std::vector<ImportEntry> imports_{};
    std::vector<PeFunctionEntry> exception_functions_{};
    std::vector<BaseRelocation> relocations_{};
    std::optional<CodeViewInfo> code_view_{};
};

} // namespace tessera
