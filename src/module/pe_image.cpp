#include "tessera/module/pe_image.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <fstream>
#include <new>

#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_reader.hpp"

namespace tessera {

std::string CodeViewInfo::guid_string() const {
    const std::uint32_t d1 = static_cast<std::uint32_t>(guid[0]) |
                             (static_cast<std::uint32_t>(guid[1]) << 8) |
                             (static_cast<std::uint32_t>(guid[2]) << 16) |
                             (static_cast<std::uint32_t>(guid[3]) << 24);
    const std::uint16_t d2 = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(guid[4]) | (static_cast<std::uint16_t>(guid[5]) << 8));
    const std::uint16_t d3 = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(guid[6]) | (static_cast<std::uint16_t>(guid[7]) << 8));
    return std::format("{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                       d1,
                       d2,
                       d3,
                       guid[8],
                       guid[9],
                       guid[10],
                       guid[11],
                       guid[12],
                       guid[13],
                       guid[14],
                       guid[15]);
}

Result<PeImage> PeImage::from_file(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return fail(ErrorCode::IoError, "PeImage::from_file", 0, "Failed to open PE file");
    }
    const auto file_size = ifs.tellg();
    if (file_size < 0x100 || file_size > (256LL * 1024LL * 1024LL)) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_file", 0, "Invalid PE file size");
    }
    ifs.seekg(0, std::ios::beg);
    try {
        std::vector<std::byte> buf(static_cast<std::size_t>(file_size));
        if (!ifs.read(reinterpret_cast<char*>(buf.data()), file_size)) {
            return fail(ErrorCode::IoError, "PeImage::from_file", 0, "Failed to read PE file bytes");
        }
        return from_raw_bytes(buf);
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PeImage::from_file");
    }
}

Result<Section> PeImage::find_section(std::string_view name) const {
    for (const auto& sec : sections_) {
        if (sec.name == name) {
            return sec;
        }
    }
    return fail(ErrorCode::NotFound, "PeImage::find_section");
}

Result<ExportTarget> PeImage::find_export(std::string_view name) const {
    if (name.empty()) {
        return fail(ErrorCode::InvalidArgument, "PeImage::find_export");
    }
    for (const auto& exp : exports_) {
        if (exp.name == name) {
            return exp;
        }
    }
    return fail(ErrorCode::NotFound, "PeImage::find_export");
}

Result<ExportTarget> PeImage::find_export(std::uint16_t ordinal) const {
    for (const auto& exp : exports_) {
        if (exp.ordinal == ordinal) {
            return exp;
        }
    }
    return fail(ErrorCode::NotFound, "PeImage::find_export");
}

Result<ImportEntry> PeImage::find_import(std::string_view module_name,
                                         std::string_view function_name) const {
    if (function_name.empty()) {
        return fail(ErrorCode::InvalidArgument, "PeImage::find_import");
    }
    auto iequals = [](std::string_view a, std::string_view b) noexcept -> bool {
        if (a.size() != b.size()) {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i) {
            const unsigned char ca = static_cast<unsigned char>(a[i]);
            const unsigned char cb = static_cast<unsigned char>(b[i]);
            const unsigned char la = (ca >= 'A' && ca <= 'Z') ? (ca + 32u) : ca;
            const unsigned char lb = (cb >= 'A' && cb <= 'Z') ? (cb + 32u) : cb;
            if (la != lb) {
                return false;
            }
        }
        return true;
    };
    for (const auto& imp : imports_) {
        if (!module_name.empty() && !iequals(imp.module_name, module_name)) {
            continue;
        }
        if (imp.function_name == function_name) {
            return imp;
        }
    }
    return fail(ErrorCode::NotFound, "PeImage::find_import");
}

} // namespace tessera
