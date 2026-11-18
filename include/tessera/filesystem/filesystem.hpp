#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"

namespace tessera::filesystem {

struct ReadFileOptions {
    std::size_t max_bytes = 64ULL * 1024ULL * 1024ULL; // 64 MiB default limit
    bool strip_utf8_bom = true;
};

struct AtomicWriteOptions {
    bool create_backup = false;
    bool write_through = true;
};

[[nodiscard]] Result<std::vector<std::byte>> read_file_bytes(
    const std::filesystem::path& path,
    ReadFileOptions options = {});

[[nodiscard]] Result<std::string> read_file_utf8(
    const std::filesystem::path& path,
    ReadFileOptions options = {});

// Writes a file atomically by writing to a temporary sibling file in the same directory,
// flushing buffers with FlushFileBuffers, and atomically replacing the target via
// ReplaceFileW / MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).
class AtomicFileWriter {
public:
    [[nodiscard]] static Status write_bytes(const std::filesystem::path& target_path,
                                            std::span<const std::byte> content,
                                            AtomicWriteOptions options = {});

    [[nodiscard]] static Status write_utf8(const std::filesystem::path& target_path,
                                           std::string_view content,
                                           AtomicWriteOptions options = {});
};

// RAII advisory/mandatory OS file lock (LockFileEx) for cross-process synchronization.
class [[nodiscard]] FileLock {
public:
    [[nodiscard]] static Result<FileLock> acquire(const std::filesystem::path& lock_file_path,
                                                  bool exclusive = true,
                                                  bool fail_immediately = true);

    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;

    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;

    ~FileLock() noexcept;

    void release() noexcept;

private:
    explicit FileLock(void* handle) noexcept : handle_(handle) {}

    void* handle_ = nullptr;
};

} // namespace tessera::filesystem
