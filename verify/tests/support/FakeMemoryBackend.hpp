#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "tessera/memory/memory_backend.hpp"
#include "tessera/process/process.hpp"

namespace tessera::testing {

// Deterministic in-memory virtual address space and fault-injecting IMemoryBackend for unit tests.
class FakeMemoryBackend final : public IMemoryBackend {
public:
    struct VirtualRegion {
        Address base{};
        std::vector<std::byte> storage{};
        MemoryState state = MemoryState::Committed;
        MemoryProtection protection = MemoryProtection::ReadWrite;
        MemoryType type = MemoryType::Private;
        std::optional<std::size_t> readable_prefix_limit{}; // Simulate partial page failure inside region
        std::optional<std::size_t> writable_prefix_limit{}; // Simulate partial write failure
        bool fail_protect = false;
        bool fail_restore_protect = false;
        std::uint32_t protect_call_count = 0;
    };

    FakeMemoryBackend() = default;

    VirtualRegion& map_region(Address base,
                              std::size_t size,
                              MemoryProtection protection = MemoryProtection::ReadWrite,
                              MemoryType type = MemoryType::Private,
                              std::byte fill_byte = std::byte{0}) {
        auto reg = std::make_unique<VirtualRegion>();
        reg->base = base;
        reg->storage.assign(size, fill_byte);
        reg->state = MemoryState::Committed;
        reg->protection = protection;
        reg->type = type;
        VirtualRegion& ref = *reg;
        regions_.push_back(std::move(reg));
        std::sort(regions_.begin(), regions_.end(), [](const auto& a, const auto& b) {
            return a->base < b->base;
        });
        return ref;
    }

    void map_uncommitted(Address base, std::size_t size, MemoryState state = MemoryState::Free) {
        auto reg = std::make_unique<VirtualRegion>();
        reg->base = base;
        reg->storage.resize(size);
        reg->state = state;
        reg->protection = MemoryProtection::NoAccess;
        regions_.push_back(std::move(reg));
        std::sort(regions_.begin(), regions_.end(), [](const auto& a, const auto& b) {
            return a->base < b->base;
        });
    }

    void poke_bytes(Address addr, std::span<const std::byte> data) {
        for (std::size_t i = 0; i < data.size(); ++i) {
            const Address cur{addr.value() + i};
            if (auto* reg = find_region_mut(cur)) {
                const auto off = static_cast<std::size_t>(cur.value() - reg->base.value());
                reg->storage[off] = data[i];
            }
        }
    }

    template <class T>
    void poke_value(Address addr, const T& val) {
        const auto raw = std::bit_cast<std::array<std::byte, sizeof(T)>>(val);
        poke_bytes(addr, raw);
    }

    [[nodiscard]] std::optional<std::byte> peek_byte(Address addr) const noexcept {
        if (const auto* reg = find_region(addr)) {
            const auto off = static_cast<std::size_t>(addr.value() - reg->base.value());
            return reg->storage[off];
        }
        return std::nullopt;
    }

    template <class T>
    [[nodiscard]] std::optional<T> peek_value(Address addr) const noexcept {
        std::array<std::byte, sizeof(T)> raw{};
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            auto b = peek_byte(Address{addr.value() + i});
            if (!b) {
                return std::nullopt;
            }
            raw[i] = *b;
        }
        return std::bit_cast<T>(raw);
    }

    [[nodiscard]] VirtualRegion* find_region_mut(Address address) noexcept {
        for (auto& r : regions_) {
            const std::uint64_t b = r->base.value();
            const std::uint64_t e = b + r->storage.size();
            if (address.value() >= b && address.value() < e) {
                return r.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] const VirtualRegion* find_region(Address address) const noexcept {
        for (const auto& r : regions_) {
            const std::uint64_t b = r->base.value();
            const std::uint64_t e = b + r->storage.size();
            if (address.value() >= b && address.value() < e) {
                return r.get();
            }
        }
        return nullptr;
    }

    // IMemoryBackend implementation
    [[nodiscard]] Result<std::size_t> read(Address address,
                                           std::span<std::byte> buffer) const override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        if (address.is_null()) {
            return fail(ErrorCode::NullAddress, "FakeMemoryBackend::read");
        }

        std::size_t copied = 0;
        while (copied < buffer.size()) {
            const Address cur{address.value() + copied};
            const auto* reg = find_region(cur);
            if (reg == nullptr || reg->state != MemoryState::Committed ||
                has_flag(reg->protection, MemoryProtection::NoAccess) ||
                has_flag(reg->protection, MemoryProtection::Guard)) {
                break;
            }
            const auto off = static_cast<std::size_t>(cur.value() - reg->base.value());
            if (reg->readable_prefix_limit.has_value() && off >= *reg->readable_prefix_limit) {
                break;
            }
            buffer[copied] = reg->storage[off];
            ++copied;
        }

        if (copied == 0) {
            return fail(ErrorCode::AccessDenied, "FakeMemoryBackend::read", 5);
        }
        return copied;
    }

    [[nodiscard]] Result<std::size_t> write(Address address,
                                            std::span<const std::byte> data) const override {
        if (data.empty()) {
            return std::size_t{0};
        }
        if (address.is_null()) {
            return fail(ErrorCode::NullAddress, "FakeMemoryBackend::write");
        }

        auto* self = const_cast<FakeMemoryBackend*>(this);
        std::size_t written = 0;
        while (written < data.size()) {
            const Address cur{address.value() + written};
            auto* reg = self->find_region_mut(cur);
            if (reg == nullptr || reg->state != MemoryState::Committed ||
                has_flag(reg->protection, MemoryProtection::Guard) ||
                !any_flag(reg->protection,
                          MemoryProtection::Write | MemoryProtection::CopyOnWrite)) {
                break;
            }
            const auto off = static_cast<std::size_t>(cur.value() - reg->base.value());
            if (reg->writable_prefix_limit.has_value() && off >= *reg->writable_prefix_limit) {
                break;
            }
            reg->storage[off] = data[written];
            ++written;
        }

        if (written == 0) {
            return fail(ErrorCode::AccessDenied, "FakeMemoryBackend::write", 5);
        }
        return written;
    }

    [[nodiscard]] Result<MemoryRegionInfo> query(Address address) const override {
        if (const auto* reg = find_region(address)) {
            return MemoryRegionInfo{
                .base = reg->base,
                .allocation_base = reg->base,
                .size = reg->storage.size(),
                .state = reg->state,
                .protection = reg->protection,
                .allocation_protection = reg->protection,
                .type = reg->type,
            };
        }

        // Find next mapped region above `address` to report a Free gap, or fail if beyond all regions
        for (const auto& r : regions_) {
            if (r->base > address) {
                return MemoryRegionInfo{
                    .base = address,
                    .allocation_base = Address{0},
                    .size = r->base.value() - address.value(),
                    .state = MemoryState::Free,
                    .protection = MemoryProtection::NoAccess,
                    .allocation_protection = MemoryProtection::NoAccess,
                    .type = MemoryType::Unknown,
                };
            }
        }

        return fail(ErrorCode::OutOfRange, "FakeMemoryBackend::query");
    }

    [[nodiscard]] Result<MemoryProtection> protect(Address address,
                                                   std::uint64_t size,
                                                   MemoryProtection new_protection) const override {
        if (address.is_null() || size == 0) {
            return fail(ErrorCode::InvalidArgument, "FakeMemoryBackend::protect");
        }
        auto* self = const_cast<FakeMemoryBackend*>(this);
        auto* reg = self->find_region_mut(address);
        if (reg == nullptr || reg->state != MemoryState::Committed) {
            return fail(ErrorCode::ProtectionFailed, "FakeMemoryBackend::protect", 487);
        }
        if (reg->fail_protect) {
            return fail(ErrorCode::ProtectionFailed, "FakeMemoryBackend::protect", 5);
        }
        if (reg->fail_restore_protect && (reg->protect_call_count % 2) == 1) {
            return fail(ErrorCode::ProtectionFailed, "FakeMemoryBackend::protect(restore)", 5);
        }

        ++reg->protect_call_count;
        const MemoryProtection prev = reg->protection;
        reg->protection = new_protection;
        return prev;
    }

    [[nodiscard]] Status flush_instruction_cache(AddressRange range) const override {
        if (range.empty()) {
            return ok();
        }
        ++const_cast<FakeMemoryBackend*>(this)->icache_flushes_;
        return ok();
    }

    [[nodiscard]] std::size_t icache_flushes() const noexcept { return icache_flushes_; }

    [[nodiscard]] static Process make_process(
        std::shared_ptr<FakeMemoryBackend> backend,
        Architecture arch = Architecture::X64,
        ProcessId pid = ProcessId{4242},
        DiagnosticObserver* observer = nullptr) {
        const ProcessInfo info{
            .pid = pid,
            .architecture = arch,
            .pointer_size = (arch == Architecture::X64) ? std::uint8_t{8} : std::uint8_t{4},
            .is_local = false,
            .granted_access = ProcessAccess::ReadWriteQuery,
            .max_application_address =
                (arch == Architecture::X64) ? 0x7FFFFFFEFFFFULL : 0xFFEFFFFFULL,
        };
        auto proc_res = Process::from_backend(info, std::move(backend), observer);
        return std::move(*proc_res);
    }

private:
    std::vector<std::unique_ptr<VirtualRegion>> regions_{};
    std::size_t icache_flushes_ = 0;
};

} // namespace tessera::testing
