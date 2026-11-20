#include "patch_hook_test_support.hpp"

namespace {

struct FakePatchWriteOps {
    std::vector<bool> protect_results;
    std::vector<bool> flush_results;
    std::vector<unsigned long> protect_errors;
    std::vector<unsigned long> flush_errors;
    std::size_t protect_index = 0;
    std::size_t flush_index = 0;
    std::size_t copy_calls = 0;
    std::vector<char> events;
    unsigned long error = 1234;
    unsigned long current_protection = 0x20UL;
    unsigned long writable_protection = 0x40UL;
    bool copied_without_write_access = false;

    bool protect(void*, std::size_t, unsigned long requested, unsigned long* previous) {
        const std::size_t call_index = protect_index++;
        const bool result = call_index < protect_results.size()
                                ? protect_results[call_index]
                                : true;
        events.push_back(result ? 'P' : 'p');
        if (result) {
            if (previous != nullptr) {
                *previous = current_protection;
            }
            current_protection = requested;
        } else {
            error = call_index < protect_errors.size()
                        ? protect_errors[call_index]
                        : 5678UL;
        }
        return result;
    }

    void copy(void* target, const std::byte* source, std::size_t size) {
        events.push_back('C');
        ++copy_calls;
        copied_without_write_access |= current_protection != writable_protection;
        std::memcpy(target, source, size);
    }

    bool flush(void*, std::size_t) {
        const std::size_t call_index = flush_index++;
        const bool result = call_index < flush_results.size()
                                ? flush_results[call_index]
                                : true;
        events.push_back(result ? 'F' : 'f');
        if (!result) {
            error = call_index < flush_errors.size()
                        ? flush_errors[call_index]
                        : 9012UL;
        }
        return result;
    }

    unsigned long last_error() const noexcept { return error; }
};

} // namespace


TEST_CASE("Native patch transaction reports initial protection failure without writing",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {false};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::InitialProtectionFailure);
    REQUIRE(ops.copy_calls == 0);
    REQUIRE(target == original);
    REQUIRE(native_error == 5678);
    REQUIRE((ops.events == std::vector<char>{'p'}));
}

TEST_CASE("Native patch transaction rolls back after instruction-cache flush failure",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, true};
    ops.flush_results = {false, true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FlushRolledBack);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(native_error == 9012);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'f', 'C', 'F', 'P'}));
}

TEST_CASE("Native patch transaction rolls back after protection restoration failure",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, false, true};
    ops.flush_results = {true, true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::ProtectionRolledBack);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(ops.protect_index == 3);
    REQUIRE(native_error == 5678);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'F', 'p', 'C', 'F', 'P'}));
}

TEST_CASE("Native patch transaction identifies an unrecoverable rollback",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true};
    ops.flush_results = {false, false, false};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FatalRollback);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(ops.current_protection == 0x40UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'f', 'C', 'f', 'f'}));
}


TEST_CASE("Native patch transaction identifies unrecoverable protection restoration",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, false, false, false};
    ops.flush_results = {true, true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FatalRollback);
    REQUIRE(target == original);
    REQUIRE(ops.protect_index == 4);
    REQUIRE(ops.current_protection == 0x40UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'F', 'p', 'C', 'F', 'p', 'p'}));
}


TEST_CASE("Native patch transaction writes and restores protection on success",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, true};
    ops.flush_results = {true};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long previous_protection = 0;
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, &previous_protection, native_error);

    REQUIRE(result == PatchWriteOutcome::Success);
    REQUIRE(target == replacement);
    REQUIRE(previous_protection == 0x20UL);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE(ops.copy_calls == 1);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'F', 'P'}));
}


TEST_CASE("Native patch transaction retries rollback flush and protection restoration",
          "[hook][native][transaction]") {
    using tessera::detail::PatchWriteOutcome;
    FakePatchWriteOps ops;
    ops.protect_results = {true, false, true};
    ops.protect_errors = {0UL, 5201UL, 5202UL};
    ops.flush_results = {false, false, true};
    ops.flush_errors = {9101UL, 9102UL, 9103UL};
    std::array<std::byte, 2> target{std::byte{0x11}, std::byte{0x22}};
    const std::array<std::byte, 2> replacement{std::byte{0xAA}, std::byte{0xBB}};
    const std::array<std::byte, 2> original{std::byte{0x11}, std::byte{0x22}};
    unsigned long native_error = 0;

    const auto result = tessera::detail::execute_patch_write(
        ops, target.data(), replacement.data(), original.data(), target.size(),
        0x40UL, 0UL, static_cast<unsigned long*>(nullptr), native_error);

    REQUIRE(result == PatchWriteOutcome::FlushRolledBack);
    REQUIRE(target == original);
    REQUIRE(ops.copy_calls == 2);
    REQUIRE(ops.protect_index == 3);
    REQUIRE(ops.flush_index == 3);
    REQUIRE(native_error == 9101UL);
    REQUIRE(ops.error == 5201UL);
    REQUIRE(ops.current_protection == 0x20UL);
    REQUIRE_FALSE(ops.copied_without_write_access);
    REQUIRE((ops.events == std::vector<char>{'P', 'C', 'f', 'C', 'f', 'F', 'p', 'P'}));
}

TEST_CASE("Patch restore refuses to overwrite bytes changed by another writer", "[patch][safety]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    auto& region = backend->map_region(Address{0x600000}, 0x1000, MemoryProtection::ReadWrite);
    const std::array<std::byte, 4> original{
        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
    backend->poke_bytes(Address{0x600100}, original);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);
    auto patch_result = Patch::nop(ProcessAddress{process, Address{0x600100}}, 4);
    REQUIRE(patch_result.has_value());
    auto patch = std::move(*patch_result);
    REQUIRE(patch.apply().has_value());

    const std::array<std::byte, 4> external{
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    backend->poke_bytes(Address{0x600100}, external);

    auto restore = patch.restore();
    REQUIRE_FALSE(restore.has_value());
    REQUIRE(restore.error().code == ErrorCode::Conflict);
    REQUIRE(patch.state() == PatchState::Applied);
    REQUIRE(*backend->peek_byte(Address{0x600100}) == std::byte{0xAA});
    (void)region;
}

TEST_CASE("PatchTransaction does not roll back patches applied before the transaction", "[patch][transaction]") {
    using namespace tessera;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x610000}, 0x1000, MemoryProtection::ReadWrite);
    const std::array<std::byte, 4> original{
        std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
    backend->poke_bytes(Address{0x610100}, original);
    Process process = FakeMemoryBackend::make_process(backend, Architecture::X64);

    auto first_result = Patch::nop(ProcessAddress{process, Address{0x610100}}, 4);
    REQUIRE(first_result.has_value());
    Patch first = std::move(*first_result);
    REQUIRE(first.apply().has_value());
    REQUIRE(first.state() == PatchState::Applied);

    PatchTransaction transaction{};
    transaction.add(std::move(first));
    auto second_result = Patch::nop(ProcessAddress{process, Address{0x999000}}, 4);
    REQUIRE(second_result.has_value());
    transaction.add(std::move(*second_result));

    const auto report = transaction.apply();
    REQUIRE_FALSE(report.succeeded);
    REQUIRE_FALSE(report.rolled_back);
    REQUIRE(report.steps[0].state == PatchState::Applied);
    REQUIRE(*backend->peek_byte(Address{0x610100}) == std::byte{0x90});

    REQUIRE(transaction.restore_all().has_value());
    REQUIRE(*backend->peek_byte(Address{0x610100}) == std::byte{0x10});
}

