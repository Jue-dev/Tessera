#include "pe_image_detail.hpp"

namespace tessera {

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
                return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0,
                            "PE32+ optional header too small");
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
                    return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0,
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
                if (exp_dir.rva >= img.size_of_image_ || exp_dir.size > (img.size_of_image_ - exp_dir.rva)) {
                    return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0,
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
                    return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0,
                                "Export count exceeds kMaxExports");
                }

                std::vector<std::string> func_names(num_funcs);
                for (std::uint32_t i = 0; i < num_names; ++i) {
                    auto name_rva = src.read_rva_val<std::uint32_t>(addr_names + i * 4u, img.sections_,
                                                                    img.size_of_image_);
                    auto ord_idx = src.read_rva_val<std::uint16_t>(addr_ords + i * 2u, img.sections_,
                                                                   img.size_of_image_);
                    if (!name_rva || !ord_idx || *ord_idx >= num_funcs) {
                        return fail(ErrorCode::InvalidPe, "PeImage::from_memory", 0,
                                    "Invalid export name/ordinal table entry");
                    }
                    auto exp_name = src.read_rva_Ascii(*name_rva, 512, img.sections_, img.size_of_image_);
                    if (!exp_name) {
                        return std::unexpected(exp_name.error());
                    }
                    func_names[*ord_idx] = std::move(*exp_name);
                }

                for (std::uint32_t i = 0; i < num_funcs; ++i) {
                    auto fn_rva = src.read_rva_val<std::uint32_t>(addr_funcs + i * 4u, img.sections_,
                                                                  img.size_of_image_);
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
                            auto tval =
                                src.read_rva_val<std::uint64_t>(cur_thunk, img.sections_, img.size_of_image_);
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
                                if (auto hint = src.read_rva_val<std::uint16_t>(ibn_rva, img.sections_,
                                                                                img.size_of_image_)) {
                                    ie.ordinal = *hint;
                                }
                                if (auto fn_name = src.read_rva_Ascii(ibn_rva + 2u, 512, img.sections_,
                                                                      img.size_of_image_)) {
                                    ie.function_name = std::move(*fn_name);
                                }
                            }
                            img.imports_.push_back(std::move(ie));
                        } else {
                            auto tval =
                                src.read_rva_val<std::uint32_t>(cur_thunk, img.sections_, img.size_of_image_);
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
                                if (auto hint = src.read_rva_val<std::uint16_t>(ibn_rva, img.sections_,
                                                                                img.size_of_image_)) {
                                    ie.ordinal = *hint;
                                }
                                if (auto fn_name = src.read_rva_Ascii(ibn_rva + 2u, 512, img.sections_,
                                                                      img.size_of_image_)) {
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

            auto relocation_entries = pe_detail::parse_base_relocations(
                src, dirs[5].rva, dirs[5].size, img.kind_, img.sections_, img.size_of_image_);
            if (!relocation_entries) {
                return std::unexpected(relocation_entries.error());
            }
            if (!relocation_entries->empty()) {
                img.exception_functions_.push_back(PeFunctionEntry{
                    .begin_rva = Rva{0xFFFFFFFFu},
                    .end_rva = Rva{0x52454C4Fu},
                    .unwind_info_rva = Rva{0x4D41524Bu},
                });
                for (const auto& relocation : *relocation_entries) {
                    img.exception_functions_.push_back(PeFunctionEntry{
                        .begin_rva = relocation.location,
                        .end_rva = Rva{relocation.type},
                        .unwind_info_rva = Rva{},
                    });
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
                                if (auto pdb = src.read_rva_Ascii(dbg_rva + 24u, 512, img.sections_,
                                                                  img.size_of_image_)) {
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

} // namespace tessera
