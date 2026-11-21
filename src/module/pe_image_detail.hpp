#pragma once

#include "tessera/module/pe_image.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "tessera/core/checked_math.hpp"
#include "tessera/memory/memory_reader.hpp"

namespace tessera {
namespace {

constexpr std::uint16_t kDosMagic = 0x5A4Du;
constexpr std::uint32_t kNtSignature = 0x00004550u;
constexpr std::uint16_t kOptMagicPe32 = 0x010Bu;
constexpr std::uint16_t kOptMagicPe32Plus = 0x020Bu;
constexpr std::uint32_t kDebugTypeCodeView = 2u;
constexpr std::uint32_t kCvSignatureRsds = 0x53445352u;

struct DataDirEntry {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

} // namespace

namespace pe_detail {

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
        std::array<std::byte, sizeof(T)> buffer{};
        auto status = read_header(offset, buffer);
        if (!status) {
            return std::unexpected(status.error());
        }
        return std::bit_cast<T>(buffer);
    }

    template <TriviallyReadable T>
    [[nodiscard]] Result<T> read_rva_val(std::uint32_t rva,
                                         std::span<const Section> sections,
                                         std::uint32_t size_of_image) const noexcept {
        std::array<std::byte, sizeof(T)> buffer{};
        auto status = read_rva(rva, buffer, sections, size_of_image);
        if (!status) {
            return std::unexpected(status.error());
        }
        return std::bit_cast<T>(buffer);
    }

    [[nodiscard]] Result<std::string> read_rva_Ascii(
        std::uint32_t rva,
        std::size_t max_len,
        std::span<const Section> sections,
        std::uint32_t size_of_image) const;
};

class MappedMemorySource final : public ImageSource {
public:
    MappedMemorySource(const Process& process, Address base) noexcept;
    [[nodiscard]] bool is_mapped() const noexcept override { return true; }
    [[nodiscard]] Status read_header(std::uint32_t offset,
                                     std::span<std::byte> out) const noexcept override;
    [[nodiscard]] Status read_rva(std::uint32_t rva,
                                  std::span<std::byte> out,
                                  std::span<const Section> sections,
                                  std::uint32_t size_of_image) const noexcept override;

private:
    MemoryReader reader_;
    Address base_;
};

class RawBufferSource final : public ImageSource {
public:
    explicit RawBufferSource(std::span<const std::byte> data) noexcept;
    [[nodiscard]] bool is_mapped() const noexcept override { return false; }
    [[nodiscard]] Status read_header(std::uint32_t offset,
                                     std::span<std::byte> out) const noexcept override;
    [[nodiscard]] Status read_rva(std::uint32_t rva,
                                  std::span<std::byte> out,
                                  std::span<const Section> sections,
                                  std::uint32_t size_of_image) const noexcept override;

private:
    std::span<const std::byte> data_;
};

} // namespace pe_detail

using pe_detail::ImageSource;
using pe_detail::MappedMemorySource;
using pe_detail::RawBufferSource;

} // namespace tessera
