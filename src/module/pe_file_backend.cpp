#include "tessera/module/pe_file_backend.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>

namespace tessera {
namespace {

template <class T>
bool read_value(std::span<const std::byte> bytes, std::size_t offset, T& out) noexcept {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        return false;
    }
    std::memcpy(&out, bytes.data() + offset, sizeof(T));
    return true;
}

Result<std::uint32_t> find_headers_size(std::span<const std::byte> bytes) noexcept {
    std::uint32_t pe_offset = 0;
    if (!read_value(bytes, 0x3c, pe_offset)) {
        return fail(ErrorCode::InvalidPe, "PeFileBackend::headers", 0, "Missing DOS header offset");
    }
    const std::size_t coff = static_cast<std::size_t>(pe_offset) + 4u;
    std::uint16_t optional_size = 0;
    if (!read_value(bytes, coff + 16u, optional_size)) {
        return fail(ErrorCode::InvalidPe, "PeFileBackend::headers", 0, "Truncated COFF header");
    }
    const std::size_t optional = coff + 20u;
    std::uint32_t headers = 0;
    if (!read_value(bytes, optional + 60u, headers) || headers == 0 || headers > bytes.size()) {
        return fail(ErrorCode::InvalidPe, "PeFileBackend::headers", 0, "Invalid SizeOfHeaders");
    }
    if (optional_size == 0) {
        return fail(ErrorCode::InvalidPe, "PeFileBackend::headers");
    }
    return headers;
}

} // namespace

Result<std::shared_ptr<PeFileBackend>> PeFileBackend::open(
    const std::filesystem::path& path, Address load_base) {
    try {
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        if (!stream) {
            return fail(ErrorCode::IoError, "PeFileBackend::open", 0, "Unable to open PE file");
        }
        const auto end = stream.tellg();
        if (end <= 0 || static_cast<std::uintmax_t>(end) >
                            static_cast<std::uintmax_t>((std::numeric_limits<std::size_t>::max)())) {
            return fail(ErrorCode::OutOfRange, "PeFileBackend::open", 0, "Invalid PE file size");
        }
        std::vector<std::byte> bytes(static_cast<std::size_t>(end));
        stream.seekg(0, std::ios::beg);
        if (!stream.read(reinterpret_cast<char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()))) {
            return fail(ErrorCode::IoError, "PeFileBackend::open", 0, "Unable to read PE file");
        }
        return from_bytes(std::move(bytes), load_base);
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PeFileBackend::open");
    } catch (const std::filesystem::filesystem_error& e) {
        return fail(ErrorCode::IoError, "PeFileBackend::open", 0, e.what());
    }
}

Result<std::shared_ptr<PeFileBackend>> PeFileBackend::from_bytes(
    std::vector<std::byte> bytes, Address load_base) {
    if (bytes.empty()) {
        return fail(ErrorCode::InvalidArgument, "PeFileBackend::from_bytes", 0, "PE buffer is empty");
    }
    auto image = PeImage::from_raw_bytes(bytes, load_base);
    if (!image) {
        return std::unexpected(image.error());
    }
    if (image->machine() != 0x014c && image->machine() != 0x8664) {
        return fail(ErrorCode::UnsupportedArchitecture, "PeFileBackend::from_bytes");
    }
    if (load_base.is_null()) {
        load_base = Address{image->image_base()};
    }
    if (load_base.is_null()) {
        return fail(ErrorCode::InvalidPe, "PeFileBackend::from_bytes", 0, "Image base is zero");
    }
    auto headers = find_headers_size(bytes);
    if (!headers) {
        return std::unexpected(headers.error());
    }
    try {
        auto backend = std::shared_ptr<PeFileBackend>(
            new PeFileBackend(std::move(bytes), std::move(*image), load_base, *headers));
        return backend;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PeFileBackend::from_bytes");
    }
}

Result<Process> PeFileBackend::make_process() {
    ProcessInfo info{};
    info.pid = ProcessId{0xfffffffdu};
    info.architecture = image_.kind() == PeKind::Pe32Plus ? Architecture::X64 : Architecture::X86;
    info.pointer_size = image_.kind() == PeKind::Pe32Plus ? 8 : 4;
    info.is_local = false;
    info.granted_access = ProcessAccess::Query | ProcessAccess::Read;
    auto last = base_.add_rva(Rva{image_.size_of_image() - 1u});
    if (!last) {
        return std::unexpected(last.error());
    }
    info.max_application_address = last->value();
    return Process::from_backend(info, shared_from_this());
}

Result<std::pair<std::uint32_t, std::uint32_t>>
PeFileBackend::mapping_for_rva(std::uint32_t rva) const noexcept {
    if (rva >= image_.size_of_image()) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::mapping_for_rva");
    }
    if (rva < headers_size_) {
        if (rva >= bytes_.size()) {
            return fail(ErrorCode::OutOfRange, "PeFileBackend::mapping_for_rva");
        }
        return std::pair{rva, headers_size_ - rva};
    }
    const Section* match = nullptr;
    for (const auto& section : image_.sections()) {
        const std::uint64_t begin = section.rva.value();
        const std::uint64_t size = section.raw_size;
        const std::uint64_t end = begin + size;
        if (size != 0 && rva >= begin && static_cast<std::uint64_t>(rva) < end) {
            if (match != nullptr) {
                return fail(ErrorCode::Conflict, "PeFileBackend::mapping_for_rva",
                            0, "Overlapping raw PE sections make the RVA ambiguous");
            }
            match = &section;
        }
    }
    if (match == nullptr) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::mapping_for_rva",
                    0, "RVA is not backed by file bytes");
    }
    const std::uint64_t delta = static_cast<std::uint64_t>(rva) - match->rva.value();
    const std::uint64_t offset = static_cast<std::uint64_t>(match->raw_offset) + delta;
    if (offset >= bytes_.size()) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::mapping_for_rva");
    }
    return std::pair{static_cast<std::uint32_t>(offset),
                     static_cast<std::uint32_t>((std::min)(
                         static_cast<std::uint64_t>(match->raw_size) - delta,
                         static_cast<std::uint64_t>(bytes_.size()) - offset))};
}

Result<std::uint32_t> PeFileBackend::rva_to_file_offset(Rva rva) const noexcept {
    auto mapping = mapping_for_rva(rva.value());
    if (!mapping) {
        return std::unexpected(mapping.error());
    }
    return mapping->first;
}

Result<Rva> PeFileBackend::file_offset_to_rva(std::uint64_t offset) const noexcept {
    if (offset >= bytes_.size()) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::file_offset_to_rva");
    }
    if (offset < headers_size_) {
        if (offset > (std::numeric_limits<std::uint32_t>::max)()) {
            return fail(ErrorCode::AddressOverflow, "PeFileBackend::file_offset_to_rva");
        }
        return Rva{static_cast<std::uint32_t>(offset)};
    }
    const Section* match = nullptr;
    for (const auto& section : image_.sections()) {
        const std::uint64_t begin = section.raw_offset;
        const std::uint64_t end = begin + section.raw_size;
        if (section.raw_size != 0 && offset >= begin && offset < end) {
            if (match != nullptr) {
                return fail(ErrorCode::Conflict, "PeFileBackend::file_offset_to_rva");
            }
            match = &section;
        }
    }
    if (match == nullptr) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::file_offset_to_rva");
    }
    const std::uint64_t rva = static_cast<std::uint64_t>(match->rva.value()) +
                              (offset - match->raw_offset);
    if (rva > (std::numeric_limits<std::uint32_t>::max)() ||
        rva >= image_.size_of_image()) {
        return fail(ErrorCode::AddressOverflow, "PeFileBackend::file_offset_to_rva");
    }
    return Rva{static_cast<std::uint32_t>(rva)};
}

Result<Address> PeFileBackend::rva_to_va(Rva rva) const noexcept {
    if (rva.value() >= image_.size_of_image()) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::rva_to_va");
    }
    return base_.add_rva(rva);
}

Result<std::size_t> PeFileBackend::read(Address address,
                                        std::span<std::byte> buffer) const {
    if (buffer.empty()) {
        return std::size_t{0};
    }
    if (address.is_null() || address < base_) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::read");
    }
    const std::uint64_t start = address.value() - base_.value();
    if (start >= image_.size_of_image()) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::read");
    }
    std::size_t copied = 0;
    while (copied < buffer.size()) {
        if (copied > (std::numeric_limits<std::uint64_t>::max)() - start) {
            if (copied != 0) return copied;
            return fail(ErrorCode::AddressOverflow, "PeFileBackend::read");
        }
        const std::uint64_t current = start + copied;
        if (current >= image_.size_of_image() ||
            current > (std::numeric_limits<std::uint32_t>::max)()) {
            break;
        }
        auto mapping = mapping_for_rva(static_cast<std::uint32_t>(current));
        if (!mapping) {
            if (copied != 0) {
                return copied;
            }
            return std::unexpected(mapping.error());
        }
        const std::size_t amount = (std::min)(
            buffer.size() - copied, static_cast<std::size_t>(mapping->second));
        if (amount == 0) {
            break;
        }
        std::memcpy(buffer.data() + copied, bytes_.data() + mapping->first, amount);
        copied += amount;
    }
    return copied;
}

Result<std::size_t> PeFileBackend::write(Address, std::span<const std::byte>) const {
    return fail(ErrorCode::AccessDenied, "PeFileBackend::write",
                0, "Offline PE backend is read-only");
}

Result<MemoryRegionInfo> PeFileBackend::query(Address address) const {
    if (address.is_null() || address < base_) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::query");
    }
    const std::uint64_t rva64 = address.value() - base_.value();
    if (rva64 >= image_.size_of_image()) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::query");
    }
    const auto rva = static_cast<std::uint32_t>(rva64);
    if (rva < headers_size_) {
        return MemoryRegionInfo{
            .base = base_,
            .allocation_base = base_,
            .size = headers_size_,
            .state = MemoryState::Committed,
            .protection = MemoryProtection::Read,
            .allocation_protection = MemoryProtection::Read,
            .type = MemoryType::Image,
        };
    }
    const Section* match = nullptr;
    for (const auto& section : image_.sections()) {
        const std::uint64_t begin = section.rva.value();
        const std::uint64_t end = begin + section.raw_size;
        if (section.raw_size != 0 && rva >= begin && rva < end) {
            if (match != nullptr) {
                return fail(ErrorCode::Conflict, "PeFileBackend::query");
            }
            match = &section;
        }
    }
    if (match == nullptr) {
        return fail(ErrorCode::OutOfRange, "PeFileBackend::query",
                    0, "RVA is unmapped or has no file-backed bytes");
    }
    MemoryProtection protection = MemoryProtection::None;
    if (match->is_readable()) {
        protection |= MemoryProtection::Read;
    }
    if (match->is_writable()) {
        protection |= MemoryProtection::Write;
    }
    if (match->is_executable()) {
        protection |= MemoryProtection::Execute;
    }
    if (protection == MemoryProtection::None) {
        protection = MemoryProtection::Read;
    }
    auto section_base = base_.add_rva(match->rva);
    if (!section_base) {
        return std::unexpected(section_base.error());
    }
    return MemoryRegionInfo{
        .base = *section_base,
        .allocation_base = base_,
        .size = (std::min)(static_cast<std::uint64_t>(match->raw_size),
                           static_cast<std::uint64_t>(image_.size_of_image()) - match->rva.value()),
        .state = MemoryState::Committed,
        .protection = protection,
        .allocation_protection = protection,
        .type = MemoryType::Image,
    };
}

Result<MemoryProtection> PeFileBackend::protect(Address, std::uint64_t,
                                                MemoryProtection) const {
    return fail(ErrorCode::AccessDenied, "PeFileBackend::protect",
                0, "Offline PE backend does not support protection changes");
}

Status PeFileBackend::flush_instruction_cache(AddressRange) const {
    return ok(); // No CPU instruction cache is modified by file-backed reads.
}

} // namespace tessera
