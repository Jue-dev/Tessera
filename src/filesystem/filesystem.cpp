#include "tessera/filesystem/filesystem.hpp"

#include <Windows.h>

#include <atomic>
#include <format>
#include <new>
#include <utility>

#include "tessera/utility/encoding.hpp"

namespace tessera::filesystem {

namespace {

std::atomic<std::uint64_t> g_temp_counter{1};

} // namespace

Result<std::vector<std::byte>> read_file_bytes(const std::filesystem::path& path,
                                               ReadFileOptions options) {
    if (path.empty()) {
        return fail(ErrorCode::InvalidArgument, "filesystem::read_file_bytes");
    }

    const HANDLE h = ::CreateFileW(path.c_str(),
                                   GENERIC_READ,
                                   FILE_SHARE_READ,
                                   nullptr,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        const ErrorCode code = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                                   ? ErrorCode::NotFound
                                   : (err == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::IoError);
        return fail(code, "CreateFileW", err);
    }

    LARGE_INTEGER file_size{};
    if (!::GetFileSizeEx(h, &file_size) || file_size.QuadPart < 0) {
        const DWORD err = ::GetLastError();
        ::CloseHandle(h);
        return fail(ErrorCode::IoError, "GetFileSizeEx", err);
    }

    const auto u_size = static_cast<std::uint64_t>(file_size.QuadPart);
    if (u_size > options.max_bytes) {
        ::CloseHandle(h);
        return fail(ErrorCode::OutOfRange,
                    "filesystem::read_file_bytes",
                    0,
                    "File size exceeds ReadFileOptions::max_bytes");
    }

    try {
        std::vector<std::byte> buffer(static_cast<std::size_t>(u_size));
        std::size_t total_read = 0;
        while (total_read < buffer.size()) {
            const auto chunk = static_cast<DWORD>(
                (std::min)(buffer.size() - total_read, std::size_t{1u << 20}));
            DWORD got = 0;
            if (!::ReadFile(h, buffer.data() + total_read, chunk, &got, nullptr)) {
                const DWORD err = ::GetLastError();
                ::CloseHandle(h);
                return fail(ErrorCode::IoError, "ReadFile", err);
            }
            if (got == 0) {
                break;
            }
            total_read += got;
        }
        ::CloseHandle(h);
        if (total_read != buffer.size()) {
            return fail(ErrorCode::PartialTransfer, "ReadFile");
        }
        return buffer;
    } catch (const std::bad_alloc&) {
        ::CloseHandle(h);
        return fail(ErrorCode::OutOfMemory, "filesystem::read_file_bytes");
    }
}

Result<std::string> read_file_utf8(const std::filesystem::path& path, ReadFileOptions options) {
    auto bytes_res = read_file_bytes(path, options);
    if (!bytes_res) {
        return std::unexpected(bytes_res.error());
    }

    std::span<const std::byte> span = *bytes_res;
    if (options.strip_utf8_bom && span.size() >= 3 &&
        span[0] == std::byte{0xEF} && span[1] == std::byte{0xBB} && span[2] == std::byte{0xBF}) {
        span = span.subspan(3);
    }

    const std::string_view sv(reinterpret_cast<const char*>(span.data()), span.size());
    if (!encoding::is_valid_utf8(sv)) {
        return fail(ErrorCode::ParseError,
                    "filesystem::read_file_utf8",
                    0,
                    "File content is not valid UTF-8");
    }

    try {
        return std::string(sv);
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "filesystem::read_file_utf8");
    }
}

Status AtomicFileWriter::write_bytes(const std::filesystem::path& target_path,
                                     std::span<const std::byte> content,
                                     AtomicWriteOptions options) {
    if (target_path.empty()) {
        return fail(ErrorCode::InvalidArgument, "AtomicFileWriter::write_bytes");
    }

    std::error_code ec;
    const auto abs_target = std::filesystem::absolute(target_path, ec);
    if (ec) {
        return fail(ErrorCode::IoError,
                    "std::filesystem::absolute",
                    static_cast<std::uint32_t>(ec.value()));
    }

    const auto parent_dir = abs_target.parent_path();
    if (!parent_dir.empty()) {
        std::filesystem::create_directories(parent_dir, ec);
        if (ec) {
            return fail(ErrorCode::IoError,
                        "std::filesystem::create_directories",
                        static_cast<std::uint32_t>(ec.value()));
        }
    }

    const std::uint64_t seq = g_temp_counter.fetch_add(1, std::memory_order_relaxed);
    const std::wstring temp_name = std::format(
        L"{}.tmp.{}.{}", abs_target.filename().wstring(), ::GetCurrentProcessId(), seq);
    const std::filesystem::path temp_path = parent_dir / temp_name;

    const DWORD flags = FILE_ATTRIBUTE_NORMAL | (options.write_through ? FILE_FLAG_WRITE_THROUGH : 0);
    const HANDLE h = ::CreateFileW(temp_path.c_str(),
                                   GENERIC_WRITE,
                                   0,
                                   nullptr,
                                   CREATE_ALWAYS,
                                   flags,
                                   nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::IoError, "CreateFileW(temp)", ::GetLastError());
    }

    std::size_t written_total = 0;
    while (written_total < content.size()) {
        const auto chunk = static_cast<DWORD>(
            (std::min)(content.size() - written_total, std::size_t{1u << 20}));
        DWORD written = 0;
        if (!::WriteFile(h, content.data() + written_total, chunk, &written, nullptr) ||
            written != chunk) {
            const DWORD err = ::GetLastError();
            ::CloseHandle(h);
            ::DeleteFileW(temp_path.c_str());
            return fail(ErrorCode::IoError, "WriteFile(temp)", err);
        }
        written_total += written;
    }

    if (!::FlushFileBuffers(h)) {
        const DWORD err = ::GetLastError();
        ::CloseHandle(h);
        ::DeleteFileW(temp_path.c_str());
        return fail(ErrorCode::IoError, "FlushFileBuffers", err);
    }
    ::CloseHandle(h);

    const DWORD target_attrs = ::GetFileAttributesW(abs_target.c_str());
    const bool target_exists = (target_attrs != INVALID_FILE_ATTRIBUTES);

    if (target_exists && options.create_backup) {
        const std::filesystem::path backup_path =
            parent_dir / (abs_target.filename().wstring() + L".bak");
        if (::ReplaceFileW(abs_target.c_str(),
                           temp_path.c_str(),
                           backup_path.c_str(),
                           REPLACEFILE_IGNORE_MERGE_ERRORS,
                           nullptr,
                           nullptr)) {
            return ok();
        }
    }

    const DWORD move_flags =
        MOVEFILE_REPLACE_EXISTING | (options.write_through ? MOVEFILE_WRITE_THROUGH : 0);
    if (!::MoveFileExW(temp_path.c_str(), abs_target.c_str(), move_flags)) {
        const DWORD err = ::GetLastError();
        ::DeleteFileW(temp_path.c_str());
        return fail(err == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::IoError,
                    "MoveFileExW",
                    err);
    }

    return ok();
}

Status AtomicFileWriter::write_utf8(const std::filesystem::path& target_path,
                                    std::string_view content,
                                    AtomicWriteOptions options) {
    if (!encoding::is_valid_utf8(content)) {
        return fail(ErrorCode::InvalidArgument,
                    "AtomicFileWriter::write_utf8",
                    0,
                    "Content is not valid UTF-8");
    }
    return write_bytes(
        target_path, std::as_bytes(std::span<const char>(content.data(), content.size())), options);
}

FileLock::FileLock(FileLock&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)) {}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
    if (this != &other) {
        release();
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

FileLock::~FileLock() noexcept {
    release();
}

void FileLock::release() noexcept {
    if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
        OVERLAPPED ov{};
        ::UnlockFileEx(static_cast<HANDLE>(handle_), 0, MAXDWORD, MAXDWORD, &ov);
        ::CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
}

Result<FileLock> FileLock::acquire(const std::filesystem::path& lock_file_path,
                                   bool exclusive,
                                   bool fail_immediately) {
    if (lock_file_path.empty()) {
        return fail(ErrorCode::InvalidArgument, "FileLock::acquire");
    }
    const auto parent = lock_file_path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }

    const HANDLE h = ::CreateFileW(lock_file_path.c_str(),
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr,
                                   OPEN_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::IoError, "CreateFileW(lock)", ::GetLastError());
    }

    OVERLAPPED ov{};
    DWORD flags = 0;
    if (exclusive) {
        flags |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    if (fail_immediately) {
        flags |= LOCKFILE_FAIL_IMMEDIATELY;
    }

    if (!::LockFileEx(h, flags, 0, MAXDWORD, MAXDWORD, &ov)) {
        const DWORD err = ::GetLastError();
        ::CloseHandle(h);
        return fail(ErrorCode::Conflict, "LockFileEx", err, "Failed to acquire file lock");
    }

    return FileLock{h};
}

} // namespace tessera::filesystem
