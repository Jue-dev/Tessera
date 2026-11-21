#include "tessera/patch/disk_patch.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#else
#include <cstdio>
#endif

namespace tessera {
namespace {

template <class T>
bool read_le(std::span<const std::byte> bytes, std::size_t offset, T& value) noexcept {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        return false;
    }
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return true;
}

template <class T>
bool write_le(std::span<std::byte> bytes, std::size_t offset, T value) noexcept {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        return false;
    }
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
    return true;
}

struct PeLayout {
    std::size_t optional_header = 0;
    std::size_t optional_size = 0;
    std::size_t checksum_offset = 0;
    std::size_t security_directory_offset = 0;
    std::uint32_t certificate_offset = 0;
    std::uint32_t certificate_size = 0;
};

Result<PeLayout> parse_layout(std::span<const std::byte> bytes) noexcept {
    std::uint16_t mz = 0;
    std::uint32_t pe = 0;
    if (!read_le(bytes, 0, mz) || mz != 0x5a4d ||
        !read_le(bytes, 0x3c, pe) || pe > bytes.size()) {
        return fail(ErrorCode::InvalidPe, "PeDiskPatcher::parse_layout");
    }
    const std::size_t coff = static_cast<std::size_t>(pe) + 4u;
    std::uint16_t optional_size = 0;
    if (!read_le(bytes, coff + 16u, optional_size)) {
        return fail(ErrorCode::InvalidPe, "PeDiskPatcher::parse_layout");
    }
    const std::size_t optional = coff + 20u;
    std::uint16_t magic = 0;
    if (!read_le(bytes, optional, magic)) {
        return fail(ErrorCode::InvalidPe, "PeDiskPatcher::parse_layout");
    }
    const std::size_t directory = optional + (magic == 0x20b ? 112u : magic == 0x10b ? 96u : 0u);
    if (directory == optional || optional_size < 68u ||
        optional > bytes.size() || optional_size > bytes.size() - optional) {
        return fail(ErrorCode::InvalidPe, "PeDiskPatcher::parse_layout");
    }
    PeLayout layout{};
    layout.optional_header = optional;
    layout.optional_size = optional_size;
    layout.checksum_offset = optional + 64u;
    if (directory + 5u * 8u <= optional + optional_size &&
        directory + 5u * 8u <= bytes.size()) {
        layout.security_directory_offset = directory + 4u * 8u;
        (void)read_le(bytes, layout.security_directory_offset, layout.certificate_offset);
        (void)read_le(bytes, layout.security_directory_offset + 4u, layout.certificate_size);
    }
    return layout;
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path) {
    try {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) {
            return fail(ErrorCode::IoError, "DiskPatchTransaction::read", 0, "Unable to open target");
        }
        auto size = in.tellg();
        if (size < 0 || static_cast<std::uintmax_t>(size) >
                            static_cast<std::uintmax_t>((std::numeric_limits<std::size_t>::max)())) {
            return fail(ErrorCode::OutOfRange, "DiskPatchTransaction::read");
        }
        std::vector<std::byte> bytes(static_cast<std::size_t>(size));
        in.seekg(0);
        if (!bytes.empty() &&
            !in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
            return fail(ErrorCode::IoError, "DiskPatchTransaction::read");
        }
        return bytes;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "DiskPatchTransaction::read");
    }
}

Status write_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return fail(ErrorCode::IoError, "DiskPatchTransaction::write", 0, "Unable to create temporary file");
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    out.flush();
    if (!out) {
        return fail(ErrorCode::IoError, "DiskPatchTransaction::write", 0, "Temporary file write failed");
    }
    out.close();
    if (!out) {
        return fail(ErrorCode::IoError, "DiskPatchTransaction::write", 0, "Temporary file close failed");
    }
    return ok();
}

Status atomic_replace(const std::filesystem::path& temp, const std::filesystem::path& target) {
#if defined(_WIN32)
    if (!::MoveFileExW(temp.c_str(), target.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return fail(ErrorCode::IoError, "MoveFileExW", ::GetLastError(), "Atomic replacement failed");
    }
#else
    if (std::rename(temp.c_str(), target.c_str()) != 0) {
        return fail(ErrorCode::IoError, "rename", 0, "Atomic replacement failed");
    }
#endif
    return ok();
}

} // namespace

Result<std::uint32_t> PeDiskPatcher::calculate_checksum(
    std::span<const std::byte> file_bytes) {
    auto layout = parse_layout(file_bytes);
    if (!layout) {
        return std::unexpected(layout.error());
    }
    std::uint64_t sum = 0;
    for (std::size_t i = 0; i < file_bytes.size(); i += 2u) {
        if (i == layout->checksum_offset || i == layout->checksum_offset + 2u) {
            continue;
        }
        std::uint16_t word = std::to_integer<std::uint8_t>(file_bytes[i]);
        if (i + 1u < file_bytes.size()) {
            word |= static_cast<std::uint16_t>(
                std::to_integer<std::uint8_t>(file_bytes[i + 1u])) << 8u;
        }
        sum += word;
        sum = (sum & 0xffffu) + (sum >> 16u);
    }
    sum = (sum & 0xffffu) + (sum >> 16u);
    sum += file_bytes.size();
    return static_cast<std::uint32_t>(sum & 0xffffffffu);
}

Result<std::vector<PeCodeCave>> PeDiskPatcher::find_code_caves(
    std::span<const std::byte> file_bytes, std::size_t min_size,
    SectionCharacteristics section_flags) {
    if (min_size == 0) {
        return fail(ErrorCode::InvalidArgument, "PeDiskPatcher::find_code_caves");
    }
    auto image = PeImage::from_raw_bytes(file_bytes);
    if (!image) {
        return std::unexpected(image.error());
    }
    std::vector<PeCodeCave> caves;
    try {
        for (const auto& section : image->sections()) {
            if (!has_flag(section.characteristics, section_flags) ||
                section.raw_size <= section.virtual_size) {
                continue;
            }
            const std::uint64_t padding_start =
                static_cast<std::uint64_t>(section.raw_offset) + section.virtual_size;
            const std::uint64_t padding_end =
                static_cast<std::uint64_t>(section.raw_offset) + section.raw_size;
            if (padding_start > file_bytes.size() || padding_end > file_bytes.size() ||
                padding_end < padding_start) {
                continue;
            }
            std::size_t run_start = 0;
            std::size_t run_size = 0;
            for (std::uint64_t offset = padding_start; offset < padding_end; ++offset) {
                const auto value = std::to_integer<std::uint8_t>(file_bytes[static_cast<std::size_t>(offset)]);
                const bool padding = value == 0x00u || value == 0x90u || value == 0xccu;
                if (padding) {
                    if (run_size == 0) {
                        run_start = static_cast<std::size_t>(offset);
                    }
                    ++run_size;
                } else {
                    if (run_size >= min_size) {
                        const std::uint64_t rva = static_cast<std::uint64_t>(section.rva.value()) +
                                                  run_start - section.raw_offset;
                        if (rva > (std::numeric_limits<std::uint32_t>::max)()) {
                            run_size = 0;
                            continue;
                        }
                        caves.push_back(PeCodeCave{Rva{static_cast<std::uint32_t>(rva)},
                                                   run_start, run_size, section.name});
                    }
                    run_size = 0;
                }
            }
            if (run_size >= min_size) {
                const std::uint64_t rva = static_cast<std::uint64_t>(section.rva.value()) +
                                          run_start - section.raw_offset;
                if (rva > (std::numeric_limits<std::uint32_t>::max)()) {
                    run_size = 0;
                    continue;
                }
                caves.push_back(PeCodeCave{Rva{static_cast<std::uint32_t>(rva)},
                                           run_start, run_size, section.name});
            }
        }
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PeDiskPatcher::find_code_caves");
    }
    return caves;
}

Status DiskPatchTransaction::add_patch(std::uint64_t file_offset,
                                        std::span<const std::byte> replacement,
                                        std::span<const std::byte> expected_original) {
    if (applied_ || replacement.empty()) {
        return fail(ErrorCode::InvalidArgument, "DiskPatchTransaction::add_patch");
    }
    if (!expected_original.empty() && expected_original.size() != replacement.size()) {
        return fail(ErrorCode::InvalidArgument, "DiskPatchTransaction::add_patch",
                    0, "Expected byte count must equal replacement byte count");
    }
    try {
        StagedPatch patch{};
        patch.offset = file_offset;
        patch.replacement.assign(replacement.begin(), replacement.end());
        patch.expected.assign(expected_original.begin(), expected_original.end());
        patches_.push_back(std::move(patch));
        return ok();
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "DiskPatchTransaction::add_patch");
    }
}

Result<DiskPatchReport> DiskPatchTransaction::apply() {
    if (applied_ || patches_.empty() || file_.empty()) {
        return fail(ErrorCode::InvalidArgument, "DiskPatchTransaction::apply");
    }
    auto original = read_file(file_);
    if (!original) {
        return std::unexpected(original.error());
    }
    auto pe = PeImage::from_raw_bytes(*original);
    if (!pe) {
        return std::unexpected(pe.error());
    }
    auto layout = parse_layout(*original);
    if (!layout) {
        return std::unexpected(layout.error());
    }
    const bool signed_file = layout->certificate_offset != 0 && layout->certificate_size != 0;
    if (signed_file && !options_.strip_signature && !options_.allow_invalidating_signature) {
        return fail(ErrorCode::AccessDenied, "DiskPatchTransaction::apply",
                    0, "Authenticode signature present; explicit signature-invalidating opt-in is required");
    }
    std::vector<StagedPatch> sorted = patches_;
    std::sort(sorted.begin(), sorted.end(),
              [](const StagedPatch& a, const StagedPatch& b) { return a.offset < b.offset; });
    std::vector<std::byte> updated = *original;
    std::vector<DiskPatchEdit> edits;
    try {
        edits.reserve(sorted.size());
        std::uint64_t previous_end = 0;
        bool first = true;
        for (const auto& patch : sorted) {
            if (patch.offset > updated.size() ||
                patch.replacement.size() > updated.size() - static_cast<std::size_t>(patch.offset)) {
                return fail(ErrorCode::OutOfRange, "DiskPatchTransaction::apply",
                            0, "Patch extends beyond the file");
            }
            const std::uint64_t end = patch.offset + patch.replacement.size();
            if (!first && patch.offset < previous_end) {
                return fail(ErrorCode::Conflict, "DiskPatchTransaction::apply",
                            0, "Overlapping disk patches are not allowed");
            }
            first = false;
            previous_end = end;
            if (!patch.expected.empty() &&
                !std::equal(patch.expected.begin(), patch.expected.end(),
                            updated.begin() + static_cast<std::ptrdiff_t>(patch.offset))) {
                return fail(ErrorCode::Conflict, "DiskPatchTransaction::apply",
                            0, "Expected original bytes do not match the target file");
            }
            std::copy(patch.replacement.begin(), patch.replacement.end(),
                      updated.begin() + static_cast<std::ptrdiff_t>(patch.offset));
            edits.push_back(DiskPatchEdit{patch.offset, patch.replacement.size()});
        }
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "DiskPatchTransaction::apply");
    }

    bool directory_cleared = false;
    if (signed_file && options_.strip_signature) {
        if (layout->security_directory_offset == 0 ||
            !write_le(std::span<std::byte>{updated}, layout->security_directory_offset, std::uint32_t{0}) ||
            !write_le(std::span<std::byte>{updated}, layout->security_directory_offset + 4u, std::uint32_t{0})) {
            return fail(ErrorCode::InvalidPe, "DiskPatchTransaction::apply",
                        0, "Unable to clear PE Security Directory");
        }
        directory_cleared = true;
    }

    std::uint32_t checksum = 0;
    if (options_.recalculate_checksum) {
        auto calculated = PeDiskPatcher::calculate_checksum(updated);
        if (!calculated) {
            return std::unexpected(calculated.error());
        }
        checksum = *calculated;
        if (!write_le(std::span<std::byte>{updated}, layout->checksum_offset, checksum)) {
            return fail(ErrorCode::InvalidPe, "DiskPatchTransaction::apply",
                        0, "Unable to update Optional Header checksum");
        }
    } else {
        (void)read_le(std::span<const std::byte>{updated}, layout->checksum_offset, checksum);
    }

    auto validated = PeImage::from_raw_bytes(updated);
    if (!validated) {
        return fail(ErrorCode::ValidationFailed, "DiskPatchTransaction::apply",
                    0, "Patched PE failed structural validation");
    }

    std::filesystem::path temp = file_;
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    temp += ".tessera." + std::to_string(nonce) + ".tmp";
    std::error_code ec;
    auto write_status = write_file(temp, updated);
    if (!write_status) {
        std::filesystem::remove(temp, ec);
        return std::unexpected(write_status.error());
    }
    auto written = read_file(temp);
    if (!written || *written != updated) {
        std::filesystem::remove(temp, ec);
        return fail(ErrorCode::IoError, "DiskPatchTransaction::apply",
                    0, "Temporary file verification failed");
    }

    std::optional<std::filesystem::path> backup;
    if (options_.create_backup) {
        backup = file_;
        *backup += options_.backup_suffix;
        std::filesystem::copy_file(file_, *backup,
                                   std::filesystem::copy_options::none, ec);
        if (ec) {
            const auto message = ec.message();
            std::error_code cleanup;
            std::filesystem::remove(temp, cleanup);
            return fail(ErrorCode::IoError, "DiskPatchTransaction::backup", 0, message);
        }
    }

    auto replaced = atomic_replace(temp, file_);
    if (!replaced) {
        std::filesystem::remove(temp, ec);
        return std::unexpected(replaced.error());
    }
    applied_ = true;
    edit_view_ = edits;
    return DiskPatchReport{
        .file = file_,
        .backup = backup,
        .original_size = original->size(),
        .final_size = updated.size(),
        .checksum = checksum,
        .signature_present_before = signed_file,
        .signature_directory_cleared = directory_cleared,
        .edits = std::move(edits),
    };
}

} // namespace tessera
