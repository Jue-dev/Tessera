#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <system_error>

#include "tessera/filesystem/filesystem.hpp"

TEST_CASE("AtomicFileWriter and FileLock", "[filesystem]") {
    using namespace tessera;

    const auto temp_dir = std::filesystem::temp_directory_path() / "tessera_fs_test";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    const auto file_path = temp_dir / "config.json";
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(file_path, "{\"ok\": true}").has_value());

    // Overwrite with backup
    REQUIRE(filesystem::AtomicFileWriter::write_utf8(
                file_path, "{\"ok\": false}", {.create_backup = true, .write_through = true})
                .has_value());

    auto content = filesystem::read_file_utf8(file_path);
    REQUIRE(content.has_value());
    REQUIRE(*content == "{\"ok\": false}");

    // A requested backup must contain the complete previous file, not merely
    // succeed at replacing the target.
    const auto backup_path = temp_dir / "config.json.bak";
    auto backup_content = filesystem::read_file_utf8(backup_path);
    REQUIRE(backup_content.has_value());
    REQUIRE(*backup_content == "{\"ok\": true}");

    // Exclusive FileLock prevents second concurrent exclusive lock on the same file
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

