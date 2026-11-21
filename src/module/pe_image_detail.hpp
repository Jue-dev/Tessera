#pragma once

#include "tessera/module/pe_image.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_reader.hpp"

namespace tessera {
namespace {

constexpr std::uint16_t kDosMagic = 0x5A4Du;      // "MZ"
constexpr std::uint32_t kNtSignature = 0x00004550u; // "PE\0\0"
constexpr std::uint16_t kOptMagicPe32 = 0x010Bu;
constexpr std::uint16_t kOptMagicPe32Plus = 0x020Bu;
constexpr std::uint32_t kDebugTypeCodeView = 2u;
constexpr std::uint32_t kCvSignatureRsds = 0x53445352u; // "RSDS"

struct DataDirEntry {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

// Abstracts reading by RVA or header offset from either mapped memory or raw file bytes.
class ImageSource {
public:
    virtual ~ImageSource() = default;
    [[nodiscard]] virtual bool is_mapped() const noexcept = 0;
    [[nodiscard]] virtual Status read_header(std::uint32_t offset,
                                             std::span<std::byte> out) const noexcept = 0;
    [[nodiscard]] virtual Status read_rva(std::uint32_t rva,
                                          std::span<std::byte> out,
                                          std::span<const Section> sections,
                                          std::uint32_t size_of_image) const noexcept = 0;

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read_header_val(std::uint32_t offset) const noexcept {
        std::array<std::byte, sizeof(T)> buf{};
        auto st = read_header(offset, buf);
        if (!st) {
            return std::unexpected(st.error());
        }
        return std::bit_cast<T>(buf);
    }

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read_rva_val(std::uint32_t rva,
                                         std::span<const Section> sections,
                                         std::uint32_t size_of_image) const noexcept {
        std::array<std::byte, sizeof(T)> buf{};
        auto st = read_rva(rva, buf, sections, size_of_image);
        if (!st) {
            return std::unexpected(st.error());
        }
        return std::bit_cast<T>(buf);
    }

    [[nodiscard]] Result<std::string> read_rva_Ascii(std::uint32_t rva,
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
        return fail(ErrorCode::InvalidPe, "PeImage::read_rva_ascii", 0, "String exceeds maximum length");
    }
};

class MappedMemorySource final : public ImageSource {
public:
    MappedMemorySource(const Process& proc, Address base) noexcept
        : reader_(proc), base_(base) {}

    [[nodiscard]] bool is_mapped() const noexcept override { return true; }

    [[nodiscard]] Status read_header(std::uint32_t offset,
                                     std::span<std::byte> out) const noexcept override {
        if (offset > 0x10000u || out.size() > 0x10000u) {
            return fail(ErrorCode::InvalidPe, "PeImage::read_header");
        }
        auto addr = base_.add_rva(Rva{offset});
        if (!addr) {
            return std::unexpected(addr.error());
        }
        auto st = reader_.read_exact(*addr, out);
        if (!st) {
            return fail(ErrorCode::InvalidPe, "PeImage::read_header", st.error().native);
        }
        return ok();
    }

    [[nodiscard]] Status read_rva(std::uint32_t rva,
                                  std::span<std::byte> out,
                                  std::span<const Section>,
                                  std::uint32_t size_of_image) const noexcept override {
        if (rva >= size_of_image || out.size() > (size_of_image - rva)) {
            return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0, "RVA range exceeds SizeOfImage");
        }
        auto addr = base_.add_rva(Rva{rva});
        if (!addr) {
            return std::unexpected(addr.error());
        }
        auto st = reader_.read_exact(*addr, out);
        if (!st) {
            return fail(ErrorCode::InvalidPe, "PeImage::read_rva", st.error().native);
        }
        return ok();
    }

private:
    MemoryReader reader_;
    Address base_;
};

class RawBufferSource final : public ImageSource {
public:
    explicit RawBufferSource(std::span<const std::byte> data) noexcept : data_(data) {}

    [[nodiscard]] bool is_mapped() const noexcept override { return false; }

    [[nodiscard]] Status read_header(std::uint32_t offset,
                                     std::span<std::byte> out) const noexcept override {
        if (offset > data_.size() || out.size() > (data_.size() - offset)) {
            return fail(ErrorCode::InvalidPe, "PeImage::read_header", 0, "Header offset out of file bounds");
        }
        std::memcpy(out.data(), data_.data() + offset, out.size());
        return ok();
    }

    [[nodiscard]] Status read_rva(std::uint32_t rva,
                                  std::span<std::byte> out,
                                  std::span<const Section> sections,
                                  std::uint32_t size_of_image) const noexcept override {
        if (rva >= size_of_image || out.size() > (size_of_image - rva)) {
            return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0, "RVA exceeds SizeOfImage");
        }
        // Translate RVA to raw file offset via sections
        for (const auto& sec : sections) {
            const std::uint32_t sec_rva = sec.rva.value();
            const std::uint32_t sec_span = (std::max)(sec.virtual_size, sec.raw_size);
            if (rva >= sec_rva && (rva - sec_rva) < sec_span) {
                const std::uint32_t delta = rva - sec_rva;
                if (delta >= sec.raw_size || out.size() > (sec.raw_size - delta)) {
                    return fail(ErrorCode::InvalidPe,
                                "PeImage::read_rva",
                                0,
                                "RVA span exceeds section RawSize");
                }
                const std::uint64_t file_off = static_cast<std::uint64_t>(sec.raw_offset) + delta;
                if (file_off > data_.size() || out.size() > (data_.size() - file_off)) {
                    return fail(ErrorCode::InvalidPe,
                                "PeImage::read_rva",
                                0,
                                "Section raw offset exceeds file size");
                }
                std::memcpy(out.data(), data_.data() + file_off, out.size());
                return ok();
            }
        }
        // Fallback for header RVAs before the first section
        if (rva < 0x1000u && rva <= data_.size() && out.size() <= (data_.size() - rva)) {
            std::memcpy(out.data(), data_.data() + rva, out.size());
            return ok();
        }
        return fail(ErrorCode::InvalidPe, "PeImage::read_rva", 0, "Unmapped RVA in raw PE file");
    }

private:
    std::span<const std::byte> data_;
};

} // namespace
} // namespace tessera
