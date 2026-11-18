#pragma once

#include <cstddef>

namespace tessera::detail {

enum class PatchWriteOutcome {
    Success,
    InitialProtectionFailure,
    FlushRolledBack,
    ProtectionRolledBack,
    FatalRollback,
};

// Ops supplies protect(), copy(), flush(), and last_error(). Production binds
// these operations to Win32; tests use a deterministic fake implementation.
template <class Ops, class Protection>
[[nodiscard]] PatchWriteOutcome execute_patch_write(
    Ops& ops,
    void* target,
    const std::byte* bytes,
    const std::byte* rollback_bytes,
    std::size_t size,
    Protection execute_protection,
    Protection requested_restore_protection,
    Protection* original_protection,
    unsigned long& native_error) noexcept {
    Protection previous{};
    if (!ops.protect(target, size, execute_protection, &previous)) {
        native_error = ops.last_error();
        return PatchWriteOutcome::InitialProtectionFailure;
    }

    const Protection restore_protection =
        requested_restore_protection != Protection{}
            ? requested_restore_protection
            : previous;
    if (original_protection != nullptr) {
        *original_protection = previous;
    }

    ops.copy(target, bytes, size);
    if (!ops.flush(target, size)) {
        native_error = ops.last_error();
        ops.copy(target, rollback_bytes, size);
        if (!ops.flush(target, size) && !ops.flush(target, size)) {
            return PatchWriteOutcome::FatalRollback;
        }
        if (!ops.protect(target, size, restore_protection, nullptr) &&
            !ops.protect(target, size, restore_protection, nullptr)) {
            return PatchWriteOutcome::FatalRollback;
        }
        return PatchWriteOutcome::FlushRolledBack;
    }

    if (ops.protect(target, size, restore_protection, nullptr)) {
        return PatchWriteOutcome::Success;
    }

    native_error = ops.last_error();
    // Failed VirtualProtect leaves the page writable; rollback needs no
    // second transition to acquire write access.
    ops.copy(target, rollback_bytes, size);
    if (!ops.flush(target, size) && !ops.flush(target, size)) {
        return PatchWriteOutcome::FatalRollback;
    }
    if (!ops.protect(target, size, restore_protection, nullptr) &&
        !ops.protect(target, size, restore_protection, nullptr)) {
        return PatchWriteOutcome::FatalRollback;
    }
    return PatchWriteOutcome::ProtectionRolledBack;
}

} // namespace tessera::detail
