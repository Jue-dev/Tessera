#include "tessera/filesystem/filesystem.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/targets/target_runtime.hpp"
#include "tessera/utility/bytes.hpp"

#include <algorithm>
#include <system_error>
#include <utility>

namespace tessera::targets {

Result<ModuleFingerprint> TargetFingerprinter::fingerprint_file(std::string module_id,
                                                                const std::filesystem::path& file_path) {
    std::error_code ec;
    const auto abs_path = std::filesystem::absolute(file_path, ec);
    if (ec || !std::filesystem::exists(abs_path, ec)) {
        return fail(ErrorCode::NotFound, "TargetFingerprinter::fingerprint_file");
    }
    const auto fsize = std::filesystem::file_size(abs_path, ec);
    if (ec) {
        return fail(ErrorCode::IoError, "std::filesystem::file_size");
    }
    const auto mtime = std::filesystem::last_write_time(abs_path, ec);
    if (ec) {
        return fail(ErrorCode::IoError, "std::filesystem::last_write_time");
    }

    if (policy_ == FingerprintPolicy::Performance) {
        const std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& entry : cache_) {
            if (entry.path == abs_path && entry.file_size == fsize && entry.last_write_time == mtime) {
                ModuleFingerprint cached = entry.fingerprint;
                cached.module_id = std::move(module_id);
                cached.from_metadata_cache = true;
                return cached;
            }
        }
    }

    auto raw = filesystem::read_file_bytes(abs_path);
    if (!raw) {
        return std::unexpected(raw.error());
    }
    auto pe = PeImage::from_raw_bytes(*raw);
    if (!pe) {
        return std::unexpected(pe.error());
    }

    ModuleFingerprint fp{};
    fp.module_id = std::move(module_id);
    fp.file_name = abs_path.filename().string();
    fp.architecture = (pe->kind() == PeKind::Pe32Plus) ? TargetArch::X64 : TargetArch::X86;
    fp.size_of_image = pe->size_of_image();
    fp.timestamp = pe->timestamp();
    fp.checksum = pe->checksum();
    if (pe->code_view().has_value()) {
        fp.codeview_guid = pe->code_view()->guid_string();
        fp.codeview_age = pe->code_view()->age;
    }
    fp.sha256 = utility::sha256_hex(*raw);
    fp.from_metadata_cache = false;

    {
        const std::lock_guard<std::mutex> lock(mutex_);
        bool updated = false;
        for (auto& entry : cache_) {
            if (entry.path == abs_path) {
                entry.file_size = fsize;
                entry.last_write_time = mtime;
                entry.fingerprint = fp;
                updated = true;
                break;
            }
        }
        if (!updated) {
            cache_.push_back(CacheEntry{
                .path = abs_path,
                .file_size = fsize,
                .last_write_time = mtime,
                .fingerprint = fp,
            });
        }
    }
    return fp;
}

Result<ModuleFingerprint> TargetFingerprinter::fingerprint_memory_module(const Process& process,
                                                                         std::string module_id,
                                                                         std::string file_name,
                                                                         AddressRange module_range) {
    if (module_range.empty()) {
        return fail(ErrorCode::InvalidArgument, "TargetFingerprinter::fingerprint_memory_module");
    }

    ModuleFingerprint fp{};
    fp.module_id = std::move(module_id);
    fp.file_name = std::move(file_name);
    fp.architecture = (process.architecture() == Architecture::X64) ? TargetArch::X64 : TargetArch::X86;
    fp.size_of_image = static_cast<std::uint32_t>(module_range.size());

    if (auto pe = PeImage::from_memory(process, module_range.begin())) {
        fp.architecture = (pe->kind() == PeKind::Pe32Plus) ? TargetArch::X64 : TargetArch::X86;
        fp.size_of_image = pe->size_of_image();
        fp.timestamp = pe->timestamp();
        fp.checksum = pe->checksum();
        if (pe->code_view().has_value()) {
            fp.codeview_guid = pe->code_view()->guid_string();
            fp.codeview_age = pe->code_view()->age;
        }
    }

    MemoryReader reader{process};
    const std::size_t hash_len =
        static_cast<std::size_t>((std::min)(module_range.size(), std::uint64_t{64 * 1024}));
    if (auto bytes = reader.read_bytes(module_range.begin(), hash_len)) {
        fp.sha256 = utility::sha256_hex(*bytes);
    }
    return fp;
}

void TargetFingerprinter::clear_cache() noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

} // namespace tessera::targets
