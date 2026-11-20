#include "patch_hook_test_support.hpp"

TEST_CASE("Patch apply, restore, expected_original, and PatchTransaction rollback", "[patch]") {
    using namespace tessera;
    using namespace tessera::literals;
    using namespace tessera::testing;

    auto backend = std::make_shared<FakeMemoryBackend>();
    backend->map_region(Address{0x500000}, 0x1000, MemoryProtection::ExecuteReadWrite);

    const std::array<std::byte, 4> orig_bytes{
        std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24}};
    backend->poke_bytes(Address{0x500100}, orig_bytes);

    Process proc = FakeMemoryBackend::make_process(backend, Architecture::X64);
    ProcessAddress target{proc, Address{0x500100}};

    // Expected original mismatch is rejected before writing
    PatchOptions bad_expect_opt{};
    bad_expect_opt.expected_original = ExpectedBytes{"FF FF FF FF"_sig};
    auto p_bad = Patch::nop(target, 4, bad_expect_opt);
    REQUIRE(p_bad.has_value());
    auto st_bad = p_bad->apply();
    REQUIRE_FALSE(st_bad.has_value());
    REQUIRE(st_bad.error().code == ErrorCode::ValidationFailed);
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});

    // Valid expected_original succeeds and auto_restore restores on scope exit
    {
        PatchOptions good_opt{};
        good_opt.auto_restore = true;
        good_opt.expected_original = ExpectedBytes{"48 89 5C ??"_sig};
        auto p_good = Patch::nop(target, 4, good_opt);
        REQUIRE(p_good.has_value());
        REQUIRE(p_good->apply().has_value());
        REQUIRE(p_good->state() == PatchState::Applied);
        REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x90});
    }
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});

    // PatchTransaction rolls back applied patches when a subsequent patch fails
    backend->poke_bytes(Address{0x500200}, orig_bytes);
    PatchTransaction tx{};
    tx.add(*Patch::nop(ProcessAddress{proc, Address{0x500100}}, 4));
    // Second patch targets unmapped memory -> fails!
    tx.add(*Patch::nop(ProcessAddress{proc, Address{0x999000}}, 4));

    const TransactionReport tx_rep = tx.apply();
    REQUIRE_FALSE(tx_rep.succeeded);
    REQUIRE(tx_rep.applied_count == 1);
    REQUIRE(tx_rep.rolled_back);
    REQUIRE(tx_rep.steps[0].state == PatchState::Restored);
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});

    // Custom Patch::create, idempotent apply/restore, and explicit PatchTransaction::restore_all
    const std::vector<std::byte> custom_bytes{std::byte{0x31}, std::byte{0xC0}};
    auto p_custom = Patch::create(target, custom_bytes);
    REQUIRE(p_custom.has_value());
    REQUIRE(p_custom->apply().has_value());
    REQUIRE(p_custom->apply().has_value()); // idempotent second apply
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x31});
    REQUIRE(p_custom->restore().has_value());
    REQUIRE(p_custom->restore().has_value()); // idempotent second restore
    REQUIRE(*backend->peek_byte(Address{0x500100}) == std::byte{0x48});
}


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

