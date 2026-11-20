#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <filesystem>
#include <string>
#include <system_error>

#include "tessera/filesystem/filesystem.hpp"

TEST_CASE("AtomicFileWriter and FileLock", "[filesystem]") {
    using namespace tessera;

    const auto temp_dir = std::filesystem::temp_directory_path() / "tessera_fs_test";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    const auto file_path = temp_dir / "config.json";
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(file_path, "{\"ok\": true}").has_value());
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(
                file_path, "{\"ok\": false}", {.create_backup = true, .write_through = true})
                .has_value());

    auto content = filesystem::read_file_utf8(file_path);
    REQUIRE(content.has_value());
    REQUIRE(*content == "{\"ok\": false}");

    const auto backup_path = temp_dir / "config.json.bak";
    auto backup_content = filesystem::read_file_utf8(backup_path);
    REQUIRE(backup_content.has_value());
    REQUIRE(*backup_content == "{\"ok\": true}");

    const auto lock_path = temp_dir / "test.lock";
    auto lock1 = filesystem::FileLock::acquire(lock_path, true, true);
    REQUIRE(lock1.has_value());
    auto lock2 = filesystem::FileLock::acquire(lock_path, true, true);
    REQUIRE_FALSE(lock2.has_value());
    REQUIRE(lock2.error().code == ErrorCode::Conflict);
    lock1->release();
    auto lock3 = filesystem::FileLock::acquire(lock_path, true, true);
    REQUIRE(lock3.has_value());
    lock3->release();

    std::filesystem::remove_all(temp_dir, ec);
}

TEST_CASE("Filesystem reports invalid, missing, oversized, and malformed paths", "[filesystem][boundary]") {
    using namespace tessera;

    const auto root = std::filesystem::temp_directory_path() / "tessera_fs_boundary_test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);

    auto empty_read = filesystem::read_file_bytes(std::filesystem::path{});
    REQUIRE_FALSE(empty_read.has_value());
    REQUIRE(empty_read.error().code == ErrorCode::InvalidArgument);

    auto empty_write = filesystem::AtomicFileWriter::write_utf8(std::filesystem::path{}, "data");
    REQUIRE_FALSE(empty_write.has_value());
    REQUIRE(empty_write.error().code == ErrorCode::InvalidArgument);

    auto missing = filesystem::read_file_utf8(root / "missing.txt");
    REQUIRE_FALSE(missing.has_value());
    REQUIRE(missing.error().code == ErrorCode::NotFound);

    std::filesystem::create_directories(root, ec);
    REQUIRE_FALSE(ec);

    auto directory_as_file = filesystem::read_file_bytes(root);
    REQUIRE_FALSE(directory_as_file.has_value());
    REQUIRE(directory_as_file.error().code == ErrorCode::AccessDenied);

    const auto file = root / "nested" / "boundary.txt";
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(file, "12345").has_value());
    auto too_large = filesystem::read_file_bytes(file, {.max_bytes = 4});
    REQUIRE_FALSE(too_large.has_value());
    REQUIRE(too_large.error().code == ErrorCode::OutOfRange);

    auto empty_limit = filesystem::read_file_bytes(file, {.max_bytes = 0});
    REQUIRE_FALSE(empty_limit.has_value());
    REQUIRE(empty_limit.error().code == ErrorCode::OutOfRange);

    auto invalid_utf8_write = filesystem::AtomicFileWriter::write_utf8(file, "\xFF");
    REQUIRE_FALSE(invalid_utf8_write.has_value());
    REQUIRE(invalid_utf8_write.error().code == ErrorCode::ParseError);

    const std::array<std::byte, 2> invalid_bytes{std::byte{0xC0}, std::byte{0xAF}};
    REQUIRE(filesystem::AtomicFileWriter::write_bytes(file, invalid_bytes).has_value());
    auto invalid_utf8_read = filesystem::read_file_utf8(file);
    REQUIRE_FALSE(invalid_utf8_read.has_value());
    REQUIRE(invalid_utf8_read.error().code == ErrorCode::ParseError);
    auto raw_read = filesystem::read_file_bytes(file);
    REQUIRE(raw_read.has_value());
    REQUIRE(raw_read->size() == invalid_bytes.size());

    const auto empty_file = root / "empty.txt";
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(empty_file, "").has_value());
    auto empty_content = filesystem::read_file_utf8(empty_file);
    REQUIRE(empty_content.has_value());
    REQUIRE(empty_content->empty());

    const auto blocker = root / "ordinary-file";
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(blocker, "not a directory").has_value());
    auto impossible = filesystem::AtomicFileWriter::write_utf8(blocker / "child" / "file.txt", "data");
    REQUIRE_FALSE(impossible.has_value());
    REQUIRE(impossible.error().code == ErrorCode::IoError);

    std::size_t temporary_files = 0;
    for (const auto& entry : std::filesystem::directory_iterator(file.parent_path())) {
        if (entry.path().filename().string().starts_with("boundary.txt.tmp.")) {
            ++temporary_files;
        }
    }
    REQUIRE(temporary_files == 0);
    std::filesystem::remove_all(root, ec);
}
