#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

#include "tessera/core/result.hpp"

namespace tessera {

// Shadow-vftable hook for a caller-owned C++ object. The object must expose
// the ABI vptr at offset zero and the caller supplies the readable slot count.
// No code page is written and no executable/RWX allocation is created.
class VTableHook {
public:
    VTableHook(const VTableHook&) = delete;
    VTableHook& operator=(const VTableHook&) = delete;
    VTableHook& operator=(VTableHook&&) = delete;

    VTableHook(VTableHook&& other) noexcept
        : object_(std::exchange(other.object_, nullptr)),
          original_table_(std::exchange(other.original_table_, nullptr)),
          original_slots_(std::move(other.original_slots_)),
          shadow_slots_(std::move(other.shadow_slots_)),
          installed_(std::exchange(other.installed_, false)) {}

    ~VTableHook() noexcept {
        if (installed_) {
            (void)restore();
        }
    }

    [[nodiscard]] static Result<VTableHook> create(void* object,
                                                    std::size_t slot_count) {
        if (object == nullptr || slot_count == 0 || slot_count > 4096) {
            return fail(ErrorCode::InvalidArgument, "VTableHook::create",
                        0, "Object and bounded non-zero vftable slot count are required");
        }

        auto** table_location = reinterpret_cast<void***>(object);
        if (*table_location == nullptr) {
            return fail(ErrorCode::InvalidArgument, "VTableHook::create",
                        0, "Object has a null vftable pointer");
        }

        try {
            std::vector<void*> originals(*table_location,
                                          *table_location + slot_count);
            std::vector<void*> shadow = originals;
            return VTableHook{object, *table_location,
                              std::move(originals), std::move(shadow)};
        } catch (const std::bad_alloc&) {
            return fail(ErrorCode::OutOfMemory, "VTableHook::create");
        }
    }

    // Configure shadow slots before installation. The object and function
    // targets must remain alive while the hook is installed.
    [[nodiscard]] Result<void*> set_slot(std::size_t slot,
                                         void* replacement) noexcept {
        if (installed_) {
            return fail(ErrorCode::Conflict, "VTableHook::set_slot", 0,
                        "Restore the object before changing shadow slots");
        }
        if (slot >= shadow_slots_.size() || replacement == nullptr) {
            return fail(ErrorCode::OutOfRange, "VTableHook::set_slot");
        }

        void* original = original_slots_[slot];
        shadow_slots_[slot] = replacement;
        return original;
    }

    template <class FunctionPointer>
        requires(std::is_pointer_v<FunctionPointer> &&
                 std::is_function_v<std::remove_pointer_t<FunctionPointer>>)
    [[nodiscard]] Result<FunctionPointer> hook(
        std::size_t slot, FunctionPointer replacement) noexcept {
        auto original = set_slot(
            slot, reinterpret_cast<void*>(
                      reinterpret_cast<std::uintptr_t>(replacement)));
        if (!original) {
            return std::unexpected(original.error());
        }
        return reinterpret_cast<FunctionPointer>(
            reinterpret_cast<std::uintptr_t>(*original));
    }

    [[nodiscard]] Status install() noexcept {
        if (object_ == nullptr || installed_) {
            return fail(ErrorCode::InvalidArgument, "VTableHook::install");
        }

        auto& vptr = *reinterpret_cast<void**>(object_);
        void* expected = original_table_;
        if (!std::atomic_ref<void*>{vptr}.compare_exchange_strong(
                expected, shadow_slots_.data(), std::memory_order_acq_rel)) {
            return fail(ErrorCode::Conflict, "VTableHook::install", 0,
                        "Object vftable changed since the shadow copy was created");
        }

        installed_ = true;
        return ok();
    }

    [[nodiscard]] Status restore() noexcept {
        if (!installed_) {
            return ok();
        }

        auto& vptr = *reinterpret_cast<void**>(object_);
        void* expected = shadow_slots_.data();
        if (!std::atomic_ref<void*>{vptr}.compare_exchange_strong(
                expected, original_table_, std::memory_order_acq_rel)) {
            return fail(ErrorCode::Conflict, "VTableHook::restore", 0,
                        "Object vftable is no longer owned by this hook");
        }

        installed_ = false;
        return ok();
    }

    [[nodiscard]] Result<void*> original(std::size_t slot) const noexcept {
        if (slot >= original_slots_.size()) {
            return fail(ErrorCode::OutOfRange, "VTableHook::original");
        }
        return original_slots_[slot];
    }

    [[nodiscard]] bool installed() const noexcept {
        return installed_;
    }

    [[nodiscard]] std::size_t slot_count() const noexcept {
        return shadow_slots_.size();
    }

private:
    VTableHook(void* object, void** original_table,
               std::vector<void*> originals,
               std::vector<void*> shadow) noexcept
        : object_(object),
          original_table_(original_table),
          original_slots_(std::move(originals)),
          shadow_slots_(std::move(shadow)) {}

    void* object_ = nullptr;
    void** original_table_ = nullptr;
    std::vector<void*> original_slots_{};
    std::vector<void*> shadow_slots_{};
    bool installed_ = false;
};

} // namespace tessera
