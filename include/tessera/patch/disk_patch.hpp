#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <utility>

#include "tessera/core/result.hpp"
#include "tessera/module/pe_image.hpp"

namespace tessera {

struct DiskPatchOptions {
    bool create_backup = true;
    bool recalculate_checksum = true;
    bool allow_invalidating_signature = false;
    bool strip_signature = false;
    std::filesystem::path backup_suffix = ".bak";
};

struct DiskPatchEdit {
    std::uint64_t file_offset = 0;
    std::size_t size = 0;
};

struct DiskPatchReport {
    std::filesystem::path file{};
    std::optional<std::filesystem::path> backup{};
    std::uint64_t original_size = 0;
    std::uint64_t final_size = 0;
    std::uint32_t checksum = 0;
    bool signature_present_before = false;
    bool signature_directory_cleared = false;
    std::vector<DiskPatchEdit> edits{};
};

struct PeCodeCave {
    Rva rva{};
    std::uint64_t file_offset = 0;
    std::size_t size = 0;
    std::string section_name{};
};

class PeDiskPatcher {
public:
    [[nodiscard]] static Result<std::uint32_t> calculate_checksum(
        std::span<const std::byte> file_bytes);
    [[nodiscard]] static Result<std::vector<PeCodeCave>> find_code_caves(
        std::span<const std::byte> file_bytes, std::size_t min_size,
        SectionCharacteristics section_flags =
            SectionCharacteristics::Code | SectionCharacteristics::Execute);
};

class DiskPatchTransaction {
public:
    explicit DiskPatchTransaction(std::filesystem::path file,
                                  DiskPatchOptions options = {})
        : file_(std::move(file)), options_(std::move(options)) {}

    [[nodiscard]] Status add_patch(std::uint64_t file_offset,
                                   std::span<const std::byte> replacement,
                                   std::span<const std::byte> expected_original = {});
    [[nodiscard]] Result<DiskPatchReport> apply();
    [[nodiscard]] std::span<const DiskPatchEdit> staged_edits() const noexcept {
        return edit_view_;
    }

private:
    struct StagedPatch {
        std::uint64_t offset = 0;
        std::vector<std::byte> replacement{};
        std::vector<std::byte> expected{};
    };

    std::filesystem::path file_{};
    DiskPatchOptions options_{};
    std::vector<StagedPatch> patches_{};
    std::vector<DiskPatchEdit> edit_view_{};
    bool applied_ = false;
};

} // namespace tessera
