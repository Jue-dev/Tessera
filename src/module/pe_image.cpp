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

Result<PeImage> PeImage::from_memory(const Process& process, Address base) {
    if (base.is_null()) {
        return fail(ErrorCode::NullAddress, "PeImage::from_memory");
    }
    MappedMemorySource src{process, base};
    // Parse using shared helper
    return [&]() -> Result<PeImage> {
        auto mz = src.read_header_val<std::uint16_t>(0);
        if (!mz || *mz != kDosMagic) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Missing MZ signature");
        }
        auto lfanew_res = src.read_header_val<std::uint32_t>(0x3Cu);
        if (!lfanew_res || *lfanew_res < 0x40u || *lfanew_res > 0x4000u) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Invalid e_lfanew");
        }
        const std::uint32_t lfanew = *lfanew_res;

        auto pe_sig = src.read_header_val<std::uint32_t>(lfanew);
        if (!pe_sig || *pe_sig != kNtSignature) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Missing PE signature");
        }

        const std::uint32_t file_hdr_off = lfanew + 4u;
        auto machine = src.read_header_val<std::uint16_t>(file_hdr_off + 0u);
        auto num_sections = src.read_header_val<std::uint16_t>(file_hdr_off + 2u);
        auto timestamp = src.read_header_val<std::uint32_t>(file_hdr_off + 4u);
        auto opt_hdr_size = src.read_header_val<std::uint16_t>(file_hdr_off + 16u);
        if (!machine || !num_sections || !timestamp || !opt_hdr_size) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Truncated COFF header");
        }
        if (*num_sections == 0 || *num_sections > kMaxSections) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Invalid section count");
        }
        if (*opt_hdr_size < 96u || *opt_hdr_size > 0x1000u) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Invalid optional header size");
        }

        const std::uint32_t opt_off = file_hdr_off + 20u;
        auto opt_magic = src.read_header_val<std::uint16_t>(opt_off);
        if (!opt_magic || (*opt_magic != kOptMagicPe32 && *opt_magic != kOptMagicPe32Plus)) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Invalid optional header magic");
        }

        PeImage img{};
        img.kind_ = (*opt_magic == kOptMagicPe32Plus) ? PeKind::Pe32Plus : PeKind::Pe32;
        img.machine_ = *machine;
        img.timestamp_ = *timestamp;
        img.loaded_base_ = base;

        auto ep = src.read_header_val<std::uint32_t>(opt_off + 16u);
        auto sz_image = src.read_header_val<std::uint32_t>(opt_off + 56u);
        auto chksum = src.read_header_val<std::uint32_t>(opt_off + 64u);
        if (!ep || !sz_image || !chksum || *sz_image < 0x100u) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "Invalid optional header fields");
        }
        img.entry_point_ = Rva{*ep};
        img.size_of_image_ = *sz_image;
        img.checksum_ = *chksum;

        std::uint32_t data_dir_off = 0;
        std::uint32_t num_rva_and_sizes = 0;
        if (img.kind_ == PeKind::Pe32Plus) {
            if (*opt_hdr_size < 112u) {
                return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0, "PE32+ optional header too small");
            }
            auto ib = src.read_header_val<std::uint64_t>(opt_off + 24u);
            auto n_dirs = src.read_header_val<std::uint32_t>(opt_off + 108u);
            if (!ib || !n_dirs) {
                return fail(ErrorCode::InvalidPe, "PeImage::from_memory");
            }
            img.image_base_ = *ib;
            num_rva_and_sizes = (std::min)(*n_dirs, 16u);
            data_dir_off = opt_off + 112u;
        } else {
            auto ib = src.read_header_val<std::uint32_t>(opt_off + 28u);
            auto n_dirs = src.read_header_val<std::uint32_t>(opt_off + 92u);
            if (!ib || !n_dirs) {
                return fail(ErrorCode::InvalidPe, "PeImage::from_memory");
            }
            img.image_base_ = *ib;
            num_rva_and_sizes = (std::min)(*n_dirs, 16u);
            data_dir_off = opt_off + 96u;
        }

        std::array<DataDirEntry, 16> dirs{};
        for (std::uint32_t i = 0; i < num_rva_and_sizes; ++i) {
            const std::uint32_t d_off = data_dir_off + i * 8u;
            if (d_off + 8u > opt_off + *opt_hdr_size) {
                break;
            }
            auto rva_v = src.read_header_val<std::uint32_t>(d_off);
            auto sz_v = src.read_header_val<std::uint32_t>(d_off + 4u);
            if (rva_v && sz_v) {
                dirs[i] = DataDirEntry{*rva_v, *sz_v};
            }
        }

        const std::uint32_t sec_table_off = opt_off + *opt_hdr_size;
        try {
            img.sections_.reserve(*num_sections);
            for (std::uint16_t i = 0; i < *num_sections; ++i) {
                std::array<std::byte, 40> sh{};
                auto st = src.read_header(sec_table_off + i * 40u, sh);
                if (!st) {
                    return std::unexpected(st.error());
                }
                std::uint32_t vsize = 0, vaddr = 0, rsize = 0, roff = 0, flags = 0;
                std::memcpy(&vsize, sh.data() + 8, 4);
                std::memcpy(&vaddr, sh.data() + 12, 4);
                std::memcpy(&rsize, sh.data() + 16, 4);
                std::memcpy(&roff, sh.data() + 20, 4);
                std::memcpy(&flags, sh.data() + 36, 4);

                if (vaddr >= img.size_of_image_) {
                    return fail(ErrorCode::InvalidPe,
                                "PeImage::from_memory",
                                0,
                                "Section VirtualAddress exceeds SizeOfImage");
                }

                std::size_t name_len = 0;
                while (name_len < 8 && sh[name_len] != std::byte{0}) {
                    ++name_len;
                }
                Section sec{};
                sec.name.assign(reinterpret_cast<const char*>(sh.data()), name_len);
                sec.rva = Rva{vaddr};
                sec.virtual_size = (std::min)(vsize, img.size_of_image_ - vaddr);
                sec.raw_offset = roff;
                sec.raw_size = rsize;
                sec.characteristics = static_cast<SectionCharacteristics>(flags);
                sec.module_base = base;
                img.sections_.push_back(std::move(sec));
            }

            // Parse Export Directory (DataDirectory[0]) if present
            const DataDirEntry exp_dir = dirs[0];
            if (exp_dir.rva != 0 && exp_dir.size >= 40u) {
                if (exp_dir.rva >= img.size_of_image_ ||
                    exp_dir.size > (img.size_of_image_ - exp_dir.rva)) {
                    return fail(ErrorCode::InvalidPe,
                                "PeImage::from_memory",
                                0,
                                "Export directory out of bounds");
                }
                std::array<std::byte, 40> ed{};
                auto st = src.read_rva(exp_dir.rva, ed, img.sections_, img.size_of_image_);
                if (!st) {
                    return std::unexpected(st.error());
                }
                std::uint32_t ordinal_base = 0, num_funcs = 0, num_names = 0;
                std::uint32_t addr_funcs = 0, addr_names = 0, addr_ords = 0;
                std::memcpy(&ordinal_base, ed.data() + 16, 4);
                std::memcpy(&num_funcs, ed.data() + 20, 4);
                std::memcpy(&num_names, ed.data() + 24, 4);
                std::memcpy(&addr_funcs, ed.data() + 28, 4);
                std::memcpy(&addr_names, ed.data() + 32, 4);
                std::memcpy(&addr_ords, ed.data() + 36, 4);

                if (num_funcs > kMaxExports || num_names > kMaxExports) {
                    return fail(ErrorCode::InvalidPe,
                                "PeImage::from_memory",
                                0,
                                "Export count exceeds kMaxExports");
                }

                std::vector<std::string> func_names(num_funcs);
                for (std::uint32_t i = 0; i < num_names; ++i) {
                    auto name_rva = src.read_rva_val<std::uint32_t>(
                        addr_names + i * 4u, img.sections_, img.size_of_image_);
                    auto ord_idx = src.read_rva_val<std::uint16_t>(
                        addr_ords + i * 2u, img.sections_, img.size_of_image_);
                    if (!name_rva || !ord_idx || *ord_idx >= num_funcs) {
                        return fail(ErrorCode::InvalidPe,
                                    "PeImage::from_memory",
                                    0,
                                    "Invalid export name/ordinal table entry");
                    }
                    auto exp_name = src.read_rva_Ascii(*name_rva, 512, img.sections_, img.size_of_image_);
                    if (!exp_name) {
                        return std::unexpected(exp_name.error());
                    }
                    func_names[*ord_idx] = std::move(*exp_name);
                }

                for (std::uint32_t i = 0; i < num_funcs; ++i) {
                    auto fn_rva = src.read_rva_val<std::uint32_t>(
                        addr_funcs + i * 4u, img.sections_, img.size_of_image_);
                    if (!fn_rva) {
                        return std::unexpected(fn_rva.error());
                    }
                    if (*fn_rva == 0) {
                        continue;
                    }
                    ExportTarget target{};
                    target.name = std::move(func_names[i]);
                    target.ordinal = static_cast<std::uint16_t>(ordinal_base + i);
                    target.rva = Rva{*fn_rva};
                    if (!base.is_null()) {
                        if (auto va = base.add_rva(target.rva)) {
                            target.address = *va;
                        }
                    }

                    // Check if RVA falls inside the export directory -> forwarder string
                    if (*fn_rva >= exp_dir.rva && (*fn_rva - exp_dir.rva) < exp_dir.size) {
                        auto fwd = src.read_rva_Ascii(*fn_rva, 260, img.sections_, img.size_of_image_);
                        if (!fwd) {
                            return std::unexpected(fwd.error());
                        }
                        target.forwarder = std::move(*fwd);
                    }
                    img.exports_.push_back(std::move(target));
                }
            }

            // Parse Import Directory (DataDirectory[1]) if present
            const DataDirEntry imp_dir = dirs[1];
            if (imp_dir.rva != 0 && imp_dir.size >= 20u && imp_dir.rva < img.size_of_image_) {
                const std::uint32_t max_descs = (std::min)(imp_dir.size / 20u, 1024u);
                for (std::uint32_t di = 0; di < max_descs; ++di) {
                    const std::uint32_t desc_rva = imp_dir.rva + di * 20u;
                    std::array<std::byte, 20> idesc{};
                    if (!src.read_rva(desc_rva, idesc, img.sections_, img.size_of_image_)) {
                        break;
                    }
                    std::uint32_t oft = 0, name_rva = 0, ft = 0;
                    std::memcpy(&oft, idesc.data() + 0, 4);
                    std::memcpy(&name_rva, idesc.data() + 12, 4);
                    std::memcpy(&ft, idesc.data() + 16, 4);
                    if (oft == 0 && name_rva == 0 && ft == 0) {
                        break;
                    }
                    auto mod_name = src.read_rva_Ascii(name_rva, 260, img.sections_, img.size_of_image_);
                    if (!mod_name) {
                        continue;
                    }
                    const std::uint32_t thunk_rva = (oft != 0) ? oft : ft;
                    if (thunk_rva == 0 || thunk_rva >= img.size_of_image_) {
                        continue;
                    }
                    const std::uint32_t step = (img.kind_ == PeKind::Pe32Plus) ? 8u : 4u;
                    for (std::uint32_t ti = 0; ti < 16384u && img.imports_.size() < kMaxImports; ++ti) {
                        const std::uint32_t cur_thunk = thunk_rva + ti * step;
                        const std::uint32_t cur_iat = (ft != 0) ? (ft + ti * step) : cur_thunk;
                        if (img.kind_ == PeKind::Pe32Plus) {
                            auto tval = src.read_rva_val<std::uint64_t>(
                                cur_thunk, img.sections_, img.size_of_image_);
                            if (!tval || *tval == 0) {
                                break;
                            }
                            ImportEntry ie{};
                            ie.module_name = *mod_name;
                            ie.iat_rva = Rva{cur_iat};
                            if ((*tval & 0x8000000000000000ULL) != 0) {
                                ie.by_ordinal = true;
                                ie.ordinal = static_cast<std::uint16_t>(*tval & 0xFFFFULL);
                            } else {
                                const std::uint32_t ibn_rva =
                                    static_cast<std::uint32_t>(*tval & 0x7FFFFFFFULL);
                                if (auto hint = src.read_rva_val<std::uint16_t>(
                                        ibn_rva, img.sections_, img.size_of_image_)) {
                                    ie.ordinal = *hint;
                                }
                                if (auto fn_name = src.read_rva_Ascii(
                                        ibn_rva + 2u, 512, img.sections_, img.size_of_image_)) {
                                    ie.function_name = std::move(*fn_name);
                                }
                            }
                            img.imports_.push_back(std::move(ie));
                        } else {
                            auto tval = src.read_rva_val<std::uint32_t>(
                                cur_thunk, img.sections_, img.size_of_image_);
                            if (!tval || *tval == 0) {
                                break;
                            }
                            ImportEntry ie{};
                            ie.module_name = *mod_name;
                            ie.iat_rva = Rva{cur_iat};
                            if ((*tval & 0x80000000u) != 0) {
                                ie.by_ordinal = true;
                                ie.ordinal = static_cast<std::uint16_t>(*tval & 0xFFFFu);
                            } else {
                                const std::uint32_t ibn_rva = (*tval & 0x7FFFFFFFu);
                                if (auto hint = src.read_rva_val<std::uint16_t>(
                                        ibn_rva, img.sections_, img.size_of_image_)) {
                                    ie.ordinal = *hint;
                                }
                                if (auto fn_name = src.read_rva_Ascii(
                                        ibn_rva + 2u, 512, img.sections_, img.size_of_image_)) {
                                    ie.function_name = std::move(*fn_name);
                                }
                            }
                            img.imports_.push_back(std::move(ie));
                        }
                    }
                }
            }

            // Parse Exception Directory / .pdata (DataDirectory[3]) on PE32+ if present
            const DataDirEntry exc_dir = dirs[3];
            if (img.kind_ == PeKind::Pe32Plus && exc_dir.rva != 0 && exc_dir.size >= 12u &&
                exc_dir.rva < img.size_of_image_) {
                const std::uint32_t count = (std::min)(
                    exc_dir.size / 12u, static_cast<std::uint32_t>(kMaxExceptionFunctions));
                img.exception_functions_.reserve((std::min)(count, 4096u));
                for (std::uint32_t i = 0; i < count; ++i) {
                    std::array<std::byte, 12> rf{};
                    if (!src.read_rva(exc_dir.rva + i * 12u, rf, img.sections_, img.size_of_image_)) {
                        break;
                    }
                    std::uint32_t b_rva = 0, e_rva = 0, u_rva = 0;
                    std::memcpy(&b_rva, rf.data() + 0, 4);
                    std::memcpy(&e_rva, rf.data() + 4, 4);
                    std::memcpy(&u_rva, rf.data() + 8, 4);
                    if (b_rva == 0 && e_rva == 0) {
                        break;
                    }
                    if (b_rva < e_rva && e_rva <= img.size_of_image_) {
                        img.exception_functions_.push_back(PeFunctionEntry{
                            .begin_rva = Rva{b_rva},
                            .end_rva = Rva{e_rva},
                            .unwind_info_rva = Rva{u_rva},
                        });
                    }
                }
            }

            // Parse Debug Directory (DataDirectory[6]) for CodeView RSDS info if present
            const DataDirEntry dbg_dir = dirs[6];
            if (dbg_dir.rva != 0 && dbg_dir.size >= 28u && dbg_dir.rva < img.size_of_image_) {
                const std::uint32_t count = (std::min)(dbg_dir.size / 28u, 16u);
                for (std::uint32_t i = 0; i < count; ++i) {
                    std::array<std::byte, 28> de{};
                    if (!src.read_rva(dbg_dir.rva + i * 28u, de, img.sections_, img.size_of_image_)) {
                        break;
                    }
                    std::uint32_t dbg_type = 0, dbg_size = 0, dbg_rva = 0;
                    std::memcpy(&dbg_type, de.data() + 12, 4);
                    std::memcpy(&dbg_size, de.data() + 16, 4);
                    std::memcpy(&dbg_rva, de.data() + 20, 4);
                    if (dbg_type == kDebugTypeCodeView && dbg_size >= 24u && dbg_rva != 0 &&
                        dbg_rva < img.size_of_image_) {
                        std::array<std::byte, 24> cv_hdr{};
                        if (src.read_rva(dbg_rva, cv_hdr, img.sections_, img.size_of_image_)) {
                            std::uint32_t cv_sig = 0;
                            std::memcpy(&cv_sig, cv_hdr.data(), 4);
                            if (cv_sig == kCvSignatureRsds) {
                                CodeViewInfo cv{};
                                std::memcpy(cv.guid.data(), cv_hdr.data() + 4, 16);
                                std::memcpy(&cv.age, cv_hdr.data() + 20, 4);
                                if (auto pdb = src.read_rva_Ascii(
                                        dbg_rva + 24u, 512, img.sections_, img.size_of_image_)) {
                                    cv.pdb_path = std::move(*pdb);
                                }
                                img.code_view_ = std::move(cv);
                                break;
                            }
                        }
                    }
                }
            }
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "PeImage::from_memory");
        }

        return img;
    }();
}

Result<PeImage> PeImage::from_raw_bytes(std::span<const std::byte> file_bytes, Address load_base) {
    if (file_bytes.size() < 0x100u) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Buffer too small for PE header");
    }
    RawBufferSource src{file_bytes};

    auto mz = src.read_header_val<std::uint16_t>(0);
    if (!mz || *mz != kDosMagic) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Missing MZ signature");
    }
    auto lfanew_res = src.read_header_val<std::uint32_t>(0x3Cu);
    if (!lfanew_res || *lfanew_res < 0x40u || *lfanew_res > file_bytes.size() - 24u) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Invalid e_lfanew");
    }
    const std::uint32_t lfanew = *lfanew_res;

    auto pe_sig = src.read_header_val<std::uint32_t>(lfanew);
    if (!pe_sig || *pe_sig != kNtSignature) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Missing PE signature");
    }

    const std::uint32_t file_hdr_off = lfanew + 4u;
    auto machine = src.read_header_val<std::uint16_t>(file_hdr_off + 0u);
    auto num_sections = src.read_header_val<std::uint16_t>(file_hdr_off + 2u);
    auto timestamp = src.read_header_val<std::uint32_t>(file_hdr_off + 4u);
    auto opt_hdr_size = src.read_header_val<std::uint16_t>(file_hdr_off + 16u);
    if (!machine || !num_sections || !timestamp || !opt_hdr_size) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Truncated COFF header");
    }
    if (*num_sections == 0 || *num_sections > kMaxSections) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Invalid section count");
    }
    if (*opt_hdr_size < 96u || *opt_hdr_size > 0x1000u) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Invalid optional header size");
    }

    const std::uint32_t opt_off = file_hdr_off + 20u;
    auto opt_magic = src.read_header_val<std::uint16_t>(opt_off);
    if (!opt_magic || (*opt_magic != kOptMagicPe32 && *opt_magic != kOptMagicPe32Plus)) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Invalid optional header magic");
    }

    PeImage img{};
    img.kind_ = (*opt_magic == kOptMagicPe32Plus) ? PeKind::Pe32Plus : PeKind::Pe32;
    img.machine_ = *machine;
    img.timestamp_ = *timestamp;
    img.loaded_base_ = load_base;

    auto ep = src.read_header_val<std::uint32_t>(opt_off + 16u);
    auto sz_image = src.read_header_val<std::uint32_t>(opt_off + 56u);
    auto chksum = src.read_header_val<std::uint32_t>(opt_off + 64u);
    if (!ep || !sz_image || !chksum || *sz_image < 0x100u) {
        return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "Invalid optional header fields");
    }
    img.entry_point_ = Rva{*ep};
    img.size_of_image_ = *sz_image;
    img.checksum_ = *chksum;

    std::uint32_t data_dir_off = 0;
    std::uint32_t num_rva_and_sizes = 0;
    if (img.kind_ == PeKind::Pe32Plus) {
        if (*opt_hdr_size < 112u) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes", 0, "PE32+ optional header too small");
        }
        auto ib = src.read_header_val<std::uint64_t>(opt_off + 24u);
        auto n_dirs = src.read_header_val<std::uint32_t>(opt_off + 108u);
        if (!ib || !n_dirs) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes");
        }
        img.image_base_ = *ib;
        num_rva_and_sizes = (std::min)(*n_dirs, 16u);
        data_dir_off = opt_off + 112u;
    } else {
        auto ib = src.read_header_val<std::uint32_t>(opt_off + 28u);
        auto n_dirs = src.read_header_val<std::uint32_t>(opt_off + 92u);
        if (!ib || !n_dirs) {
            return fail(ErrorCode::InvalidPe, "PeImage::from_raw_bytes");
        }
        img.image_base_ = *ib;
        num_rva_and_sizes = (std::min)(*n_dirs, 16u);
        data_dir_off = opt_off + 96u;
    }

    std::array<DataDirEntry, 16> dirs{};
    for (std::uint32_t i = 0; i < num_rva_and_sizes; ++i) {
        const std::uint32_t d_off = data_dir_off + i * 8u;
        if (d_off + 8u > opt_off + *opt_hdr_size) {
            break;
        }
        auto rva_v = src.read_header_val<std::uint32_t>(d_off);
        auto sz_v = src.read_header_val<std::uint32_t>(d_off + 4u);
        if (rva_v && sz_v) {
            dirs[i] = DataDirEntry{*rva_v, *sz_v};
        }
    }

    const std::uint32_t sec_table_off = opt_off + *opt_hdr_size;
    try {
        img.sections_.reserve(*num_sections);
        for (std::uint16_t i = 0; i < *num_sections; ++i) {
            std::array<std::byte, 40> sh{};
            auto st = src.read_header(sec_table_off + i * 40u, sh);
            if (!st) {
                return std::unexpected(st.error());
            }
            std::uint32_t vsize = 0, vaddr = 0, rsize = 0, roff = 0, flags = 0;
            std::memcpy(&vsize, sh.data() + 8, 4);
            std::memcpy(&vaddr, sh.data() + 12, 4);
            std::memcpy(&rsize, sh.data() + 16, 4);
            std::memcpy(&roff, sh.data() + 20, 4);
            std::memcpy(&flags, sh.data() + 36, 4);

            if (vaddr >= img.size_of_image_) {
                return fail(ErrorCode::InvalidPe,
                            "PeImage::from_raw_bytes",
                            0,
                            "Section VirtualAddress exceeds SizeOfImage");
            }
            if (rsize > 0 && (roff > file_bytes.size() || rsize > (file_bytes.size() - roff))) {
                return fail(ErrorCode::InvalidPe,
                            "PeImage::from_raw_bytes",
                            0,
                            "Section raw data exceeds file size");
            }

            std::size_t name_len = 0;
            while (name_len < 8 && sh[name_len] != std::byte{0}) {
                ++name_len;
            }
            Section sec{};
            sec.name.assign(reinterpret_cast<const char*>(sh.data()), name_len);
            sec.rva = Rva{vaddr};
            sec.virtual_size = (std::min)(vsize, img.size_of_image_ - vaddr);
            sec.raw_offset = roff;
            sec.raw_size = rsize;
            sec.characteristics = static_cast<SectionCharacteristics>(flags);
            sec.module_base = load_base;
            img.sections_.push_back(std::move(sec));
        }

        // Export directory
        const DataDirEntry exp_dir = dirs[0];
        if (exp_dir.rva != 0 && exp_dir.size >= 40u) {
            if (exp_dir.rva >= img.size_of_image_ ||
                exp_dir.size > (img.size_of_image_ - exp_dir.rva)) {
                return fail(ErrorCode::InvalidPe,
                            "PeImage::from_raw_bytes",
                            0,
                            "Export directory out of bounds");
            }
            std::array<std::byte, 40> ed{};
            auto st = src.read_rva(exp_dir.rva, ed, img.sections_, img.size_of_image_);
            if (!st) {
                return std::unexpected(st.error());
            }
            std::uint32_t ordinal_base = 0, num_funcs = 0, num_names = 0;
            std::uint32_t addr_funcs = 0, addr_names = 0, addr_ords = 0;
            std::memcpy(&ordinal_base, ed.data() + 16, 4);
            std::memcpy(&num_funcs, ed.data() + 20, 4);
            std::memcpy(&num_names, ed.data() + 24, 4);
            std::memcpy(&addr_funcs, ed.data() + 28, 4);
            std::memcpy(&addr_names, ed.data() + 32, 4);
            std::memcpy(&addr_ords, ed.data() + 36, 4);

            if (num_funcs > kMaxExports || num_names > kMaxExports) {
                return fail(ErrorCode::InvalidPe,
                            "PeImage::from_raw_bytes",
                            0,
                            "Export count exceeds kMaxExports");
            }

            std::vector<std::string> func_names(num_funcs);
            for (std::uint32_t i = 0; i < num_names; ++i) {
                auto name_rva = src.read_rva_val<std::uint32_t>(
                    addr_names + i * 4u, img.sections_, img.size_of_image_);
                auto ord_idx = src.read_rva_val<std::uint16_t>(
                    addr_ords + i * 2u, img.sections_, img.size_of_image_);
                if (!name_rva || !ord_idx || *ord_idx >= num_funcs) {
                    return fail(ErrorCode::InvalidPe,
                                "PeImage::from_raw_bytes",
                                0,
                                "Invalid export name/ordinal table entry");
                }
                auto exp_name = src.read_rva_Ascii(*name_rva, 512, img.sections_, img.size_of_image_);
                if (!exp_name) {
                    return std::unexpected(exp_name.error());
                }
                func_names[*ord_idx] = std::move(*exp_name);
            }

            for (std::uint32_t i = 0; i < num_funcs; ++i) {
                auto fn_rva = src.read_rva_val<std::uint32_t>(
                    addr_funcs + i * 4u, img.sections_, img.size_of_image_);
                if (!fn_rva) {
                    return std::unexpected(fn_rva.error());
                }
                if (*fn_rva == 0) {
                    continue;
                }
                ExportTarget target{};
                target.name = std::move(func_names[i]);
                target.ordinal = static_cast<std::uint16_t>(ordinal_base + i);
                target.rva = Rva{*fn_rva};
                if (!load_base.is_null()) {
                    if (auto va = load_base.add_rva(target.rva)) {
                        target.address = *va;
                    }
                }
                if (*fn_rva >= exp_dir.rva && (*fn_rva - exp_dir.rva) < exp_dir.size) {
                    auto fwd = src.read_rva_Ascii(*fn_rva, 260, img.sections_, img.size_of_image_);
                    if (!fwd) {
                        return std::unexpected(fwd.error());
                    }
                    target.forwarder = std::move(*fwd);
                }
                img.exports_.push_back(std::move(target));
            }
        }

        // Import directory
        const DataDirEntry imp_dir = dirs[1];
        if (imp_dir.rva != 0 && imp_dir.size >= 20u && imp_dir.rva < img.size_of_image_) {
            const std::uint32_t max_descs = (std::min)(imp_dir.size / 20u, 1024u);
            for (std::uint32_t di = 0; di < max_descs; ++di) {
                const std::uint32_t desc_rva = imp_dir.rva + di * 20u;
                std::array<std::byte, 20> idesc{};
                if (!src.read_rva(desc_rva, idesc, img.sections_, img.size_of_image_)) {
                    break;
                }
                std::uint32_t oft = 0, name_rva = 0, ft = 0;
                std::memcpy(&oft, idesc.data() + 0, 4);
                std::memcpy(&name_rva, idesc.data() + 12, 4);
                std::memcpy(&ft, idesc.data() + 16, 4);
                if (oft == 0 && name_rva == 0 && ft == 0) {
                    break;
                }
                auto mod_name = src.read_rva_Ascii(name_rva, 260, img.sections_, img.size_of_image_);
                if (!mod_name) {
                    continue;
                }
                const std::uint32_t thunk_rva = (oft != 0) ? oft : ft;
                if (thunk_rva == 0 || thunk_rva >= img.size_of_image_) {
                    continue;
                }
                const std::uint32_t step = (img.kind_ == PeKind::Pe32Plus) ? 8u : 4u;
                for (std::uint32_t ti = 0; ti < 16384u && img.imports_.size() < kMaxImports; ++ti) {
                    const std::uint32_t cur_thunk = thunk_rva + ti * step;
                    const std::uint32_t cur_iat = (ft != 0) ? (ft + ti * step) : cur_thunk;
                    if (img.kind_ == PeKind::Pe32Plus) {
                        auto tval = src.read_rva_val<std::uint64_t>(
                            cur_thunk, img.sections_, img.size_of_image_);
                        if (!tval || *tval == 0) {
                            break;
                        }
                        ImportEntry ie{};
                        ie.module_name = *mod_name;
                        ie.iat_rva = Rva{cur_iat};
                        if ((*tval & 0x8000000000000000ULL) != 0) {
                            ie.by_ordinal = true;
                            ie.ordinal = static_cast<std::uint16_t>(*tval & 0xFFFFULL);
                        } else {
                            const std::uint32_t ibn_rva =
                                static_cast<std::uint32_t>(*tval & 0x7FFFFFFFULL);
                            if (auto hint = src.read_rva_val<std::uint16_t>(
                                    ibn_rva, img.sections_, img.size_of_image_)) {
                                ie.ordinal = *hint;
                            }
                            if (auto fn_name = src.read_rva_Ascii(
                                    ibn_rva + 2u, 512, img.sections_, img.size_of_image_)) {
                                ie.function_name = std::move(*fn_name);
                            }
                        }
                        img.imports_.push_back(std::move(ie));
                    } else {
                        auto tval = src.read_rva_val<std::uint32_t>(
                            cur_thunk, img.sections_, img.size_of_image_);
                        if (!tval || *tval == 0) {
                            break;
                        }
                        ImportEntry ie{};
                        ie.module_name = *mod_name;
                        ie.iat_rva = Rva{cur_iat};
                        if ((*tval & 0x80000000u) != 0) {
                            ie.by_ordinal = true;
                            ie.ordinal = static_cast<std::uint16_t>(*tval & 0xFFFFu);
                        } else {
                            const std::uint32_t ibn_rva = (*tval & 0x7FFFFFFFu);
                            if (auto hint = src.read_rva_val<std::uint16_t>(
                                    ibn_rva, img.sections_, img.size_of_image_)) {
                                ie.ordinal = *hint;
                            }
                            if (auto fn_name = src.read_rva_Ascii(
                                    ibn_rva + 2u, 512, img.sections_, img.size_of_image_)) {
                                ie.function_name = std::move(*fn_name);
                            }
                        }
                        img.imports_.push_back(std::move(ie));
                    }
                }
            }
        }

        // Exception directory (.pdata) on PE32+
        const DataDirEntry exc_dir = dirs[3];
        if (img.kind_ == PeKind::Pe32Plus && exc_dir.rva != 0 && exc_dir.size >= 12u &&
            exc_dir.rva < img.size_of_image_) {
            const std::uint32_t count =
                (std::min)(exc_dir.size / 12u, static_cast<std::uint32_t>(kMaxExceptionFunctions));
            img.exception_functions_.reserve((std::min)(count, 4096u));
            for (std::uint32_t i = 0; i < count; ++i) {
                std::array<std::byte, 12> rf{};
                if (!src.read_rva(exc_dir.rva + i * 12u, rf, img.sections_, img.size_of_image_)) {
                    break;
                }
                std::uint32_t b_rva = 0, e_rva = 0, u_rva = 0;
                std::memcpy(&b_rva, rf.data() + 0, 4);
                std::memcpy(&e_rva, rf.data() + 4, 4);
                std::memcpy(&u_rva, rf.data() + 8, 4);
                if (b_rva == 0 && e_rva == 0) {
                    break;
                }
                if (b_rva < e_rva && e_rva <= img.size_of_image_) {
                    img.exception_functions_.push_back(PeFunctionEntry{
                        .begin_rva = Rva{b_rva},
                        .end_rva = Rva{e_rva},
                        .unwind_info_rva = Rva{u_rva},
                    });
                }
            }
        }

        // Debug directory
        const DataDirEntry dbg_dir = dirs[6];
        if (dbg_dir.rva != 0 && dbg_dir.size >= 28u && dbg_dir.rva < img.size_of_image_) {
            const std::uint32_t count = (std::min)(dbg_dir.size / 28u, 16u);
            for (std::uint32_t i = 0; i < count; ++i) {
                std::array<std::byte, 28> de{};
                if (!src.read_rva(dbg_dir.rva + i * 28u, de, img.sections_, img.size_of_image_)) {
                    break;
                }
                std::uint32_t dbg_type = 0, dbg_size = 0, dbg_rva = 0;
                std::memcpy(&dbg_type, de.data() + 12, 4);
                std::memcpy(&dbg_size, de.data() + 16, 4);
                std::memcpy(&dbg_rva, de.data() + 20, 4);
                if (dbg_type == kDebugTypeCodeView && dbg_size >= 24u && dbg_rva != 0 &&
                    dbg_rva < img.size_of_image_) {
                    std::array<std::byte, 24> cv_hdr{};
                    if (src.read_rva(dbg_rva, cv_hdr, img.sections_, img.size_of_image_)) {
                        std::uint32_t cv_sig = 0;
                        std::memcpy(&cv_sig, cv_hdr.data(), 4);
                        if (cv_sig == kCvSignatureRsds) {
                            CodeViewInfo cv{};
                            std::memcpy(cv.guid.data(), cv_hdr.data() + 4, 16);
                            std::memcpy(&cv.age, cv_hdr.data() + 20, 4);
                            if (auto pdb = src.read_rva_Ascii(
                                    dbg_rva + 24u, 512, img.sections_, img.size_of_image_)) {
                                cv.pdb_path = std::move(*pdb);
                            }
                            img.code_view_ = std::move(cv);
                            break;
                        }
                    }
                }
            }
        }
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "PeImage::from_raw_bytes");
    }

    return img;
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
