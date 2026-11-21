#include "pe_image_detail.hpp"

#include <cstring>

namespace tessera::pe_detail {

Result<std::vector<BaseRelocation>> parse_base_relocations(
    const ImageSource& source,
    std::uint32_t directory_rva,
    std::uint32_t directory_size,
    PeKind kind,
    std::span<const Section> sections,
    std::uint32_t size_of_image) {
    if (directory_rva == 0 && directory_size == 0) {
        return std::vector<BaseRelocation>{};
    }
    if (directory_rva == 0 || directory_size < 8u ||
        directory_rva >= size_of_image ||
        directory_size > size_of_image - directory_rva) {
        return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                    "Base relocation directory is outside the image bounds");
    }

    constexpr std::size_t kMaxRelocationEntries = 1'000'000;
    try {
        std::vector<BaseRelocation> relocations;
        std::uint32_t cursor = 0;
        while (cursor < directory_size) {
            const std::uint32_t remaining = directory_size - cursor;
            if (remaining < 8u) {
                return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                            "Truncated base relocation block header");
            }
            auto block_rva = checked_add<std::uint32_t>(directory_rva, cursor);
            if (!block_rva) {
                return fail(ErrorCode::InvalidPe, "PeImage::relocations");
            }
            auto page = source.read_rva_val<std::uint32_t>(*block_rva, sections, size_of_image);
            auto block_size = source.read_rva_val<std::uint32_t>(*block_rva + 4u, sections, size_of_image);
            if (!page || !block_size || (*page & 0xFFFu) != 0 ||
                *block_size < 8u || ((*block_size - 8u) % 2u) != 0 ||
                *block_size > remaining) {
                return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                            "Malformed base relocation block");
            }
            if (*page >= size_of_image) {
                return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                            "Relocation page RVA exceeds SizeOfImage");
            }

            const std::uint32_t entry_count = (*block_size - 8u) / 2u;
            if (entry_count > kMaxRelocationEntries - relocations.size()) {
                return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                            "Relocation entry count exceeds the safety limit");
            }
            for (std::uint32_t i = 0; i < entry_count; ++i) {
                const std::uint32_t entry_offset = 8u + i * 2u;
                auto entry_rva = checked_add<std::uint32_t>(*block_rva, entry_offset);
                if (!entry_rva) {
                    return fail(ErrorCode::InvalidPe, "PeImage::relocations");
                }
                auto entry = source.read_rva_val<std::uint16_t>(*entry_rva, sections, size_of_image);
                if (!entry) {
                    return std::unexpected(entry.error());
                }
                const std::uint8_t type = static_cast<std::uint8_t>(*entry >> 12u);
                const std::uint32_t offset = static_cast<std::uint32_t>(*entry & 0x0FFFu);
                if (type == 0u) {
                    continue;
                }
                auto location = checked_add<std::uint32_t>(*page, offset);
                if (!location || *location >= size_of_image) {
                    return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                                "Relocation target exceeds SizeOfImage");
                }
                const std::uint32_t width =
                    type == 10u ? 8u : (type == 3u ? 4u : 1u);
                if (width > size_of_image - *location) {
                    return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                                "Relocation target width exceeds SizeOfImage");
                }
                if (kind == PeKind::Pe32 && type == 10u) {
                    return fail(ErrorCode::InvalidPe, "PeImage::relocations", 0,
                                "Relocation type is incompatible with the PE architecture");
                }
                relocations.push_back(BaseRelocation{.location = Rva{*location}, .type = type});
            }
            cursor += *block_size;
        }
        return relocations;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PeImage::relocations");
    }
}

Result<std::string> ImageSource::read_rva_Ascii(
    std::uint32_t rva,
    std::size_t max_len,
    std::span<const Section> sections,
    std::uint32_t size_of_image) const {
    if (rva == 0 || rva >= size_of_image) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_rva_ascii", 0, "RVA out of bounds");
    }
    std::string out;
    for (std::size_t i = 0; i < max_len; ++i) {
        if (rva + i >= size_of_image) {
            return fail(ErrorCode::InvalidPe,
                        "PeImage::read_rva_ascii",
                        0,
                        "Unterminated string at image boundary");
        }
        auto ch = read_rva_val<char>(static_cast<std::uint32_t>(rva + i), sections, size_of_image);
        if (!ch) {
            return std::unexpected(ch.error());
        }
        if (*ch == '\0') {
            return out;
        }
        out.push_back(*ch);
    }
    return fail(ErrorCode::InvalidPe, "PeImage::read_rva_ascii", 0,
                "String exceeds maximum length");
}

MappedMemorySource::MappedMemorySource(const Process& process, Address base) noexcept
    : reader_(process), base_(base) {}

Status MappedMemorySource::read_header(
    std::uint32_t offset, std::span<std::byte> out) const noexcept {
    if (offset > 0x10000u || out.size() > 0x10000u) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_header");
    }
    auto address = base_.add_rva(Rva{offset});
    if (!address) {
        return std::unexpected(address.error());
    }
    auto status = reader_.read_exact(*address, out);
    if (!status) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_header", status.error().native);
    }
    return ok();
}

Status MappedMemorySource::read_rva(
    std::uint32_t rva,
    std::span<std::byte> out,
    std::span<const Section>,
    std::uint32_t size_of_image) const noexcept {
    if (rva >= size_of_image || out.size() > (size_of_image - rva)) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0,
                    "RVA range exceeds SizeOfImage");
    }
    auto address = base_.add_rva(Rva{rva});
    if (!address) {
        return std::unexpected(address.error());
    }
    auto status = reader_.read_exact(*address, out);
    if (!status) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_rva", status.error().native);
    }
    return ok();
}

RawBufferSource::RawBufferSource(std::span<const std::byte> data) noexcept
    : data_(data) {}

Status RawBufferSource::read_header(
    std::uint32_t offset, std::span<std::byte> out) const noexcept {
    if (offset > data_.size() || out.size() > (data_.size() - offset)) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_header", 0,
                    "Header offset out of file bounds");
    }
    std::memcpy(out.data(), data_.data() + offset, out.size());
    return ok();
}

Status RawBufferSource::read_rva(
    std::uint32_t rva,
    std::span<std::byte> out,
    std::span<const Section> sections,
    std::uint32_t size_of_image) const noexcept {
    if (rva >= size_of_image || out.size() > (size_of_image - rva)) {
        return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0, "RVA exceeds SizeOfImage");
    }
    for (const auto& section : sections) {
        const std::uint32_t section_rva = section.rva.value();
        const std::uint32_t section_span = (std::max)(section.virtual_size, section.raw_size);
        if (rva >= section_rva && (rva - section_rva) < section_span) {
            const std::uint32_t delta = rva - section_rva;
            if (delta >= section.raw_size || out.size() > (section.raw_size - delta)) {
                return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0,
                            "RVA span exceeds section RawSize");
            }
            const std::uint64_t file_offset = static_cast<std::uint64_t>(section.raw_offset) + delta;
            if (file_offset > data_.size() || out.size() > (data_.size() - file_offset)) {
                return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0,
                            "Section raw offset exceeds file size");
            }
            std::memcpy(out.data(), data_.data() + file_offset, out.size());
            return ok();
        }
    }
    if (rva < 0x1000u && rva <= data_.size() && out.size() <= (data_.size() - rva)) {
        std::memcpy(out.data(), data_.data() + rva, out.size());
        return ok();
    }
    return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0, "Unmapped RVA in raw PE file");
}

} // namespace tessera::pe_detail
