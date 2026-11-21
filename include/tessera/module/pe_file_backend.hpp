#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "tessera/memory/memory_backend.hpp"
#include "tessera/module/pe_image.hpp"

namespace tessera {

// Read-only MemoryBackend over the file-backed portions of a raw PE image.
// Writes and protection changes are deliberately rejected; use DiskPatchTransaction
// for explicit, transactional on-disk edits.
class PeFileBackend final : public IMemoryBackend,
                            public std::enable_shared_from_this<PeFileBackend> {
public:
    [[nodiscard]] static Result<std::shared_ptr<PeFileBackend>> open(
        const std::filesystem::path& path, Address load_base = {});
    [[nodiscard]] static Result<std::shared_ptr<PeFileBackend>> from_bytes(
        std::vector<std::byte> bytes, Address load_base = {});

    [[nodiscard]] Result<Process> make_process();
    [[nodiscard]] const PeImage& image() const noexcept { return image_; }
    [[nodiscard]] Address base() const noexcept { return base_; }
    [[nodiscard]] std::span<const std::byte> file_bytes() const noexcept { return bytes_; }

    [[nodiscard]] Result<std::uint32_t> rva_to_file_offset(Rva rva) const noexcept;
    [[nodiscard]] Result<Rva> file_offset_to_rva(std::uint64_t offset) const noexcept;
    [[nodiscard]] Result<Address> rva_to_va(Rva rva) const noexcept;

    [[nodiscard]] Result<std::size_t> read(Address address,
                                           std::span<std::byte> buffer) const override;
    [[nodiscard]] Result<std::size_t> write(Address address,
                                            std::span<const std::byte> data) const override;
    [[nodiscard]] Result<MemoryRegionInfo> query(Address address) const override;
    [[nodiscard]] Result<MemoryProtection> protect(Address address,
                                                   std::uint64_t size,
                                                   MemoryProtection new_protection) const override;
    [[nodiscard]] Status flush_instruction_cache(AddressRange range) const override;

private:
    PeFileBackend(std::vector<std::byte> bytes, PeImage image,
                  Address base, std::uint32_t headers_size) noexcept
        : bytes_(std::move(bytes)), image_(std::move(image)), base_(base),
          headers_size_(headers_size) {}

    [[nodiscard]] Result<std::pair<std::uint32_t, std::uint32_t>>
    mapping_for_rva(std::uint32_t rva) const noexcept;

    std::vector<std::byte> bytes_{};
    PeImage image_{};
    Address base_{};
    std::uint32_t headers_size_ = 0;
};

} // namespace tessera
