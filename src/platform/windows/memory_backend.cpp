#include "tessera/memory/memory_backend.hpp"

#include <Windows.h>

#include <limits>
#include <memory>

#include "platform/windows/process_state.hpp"
#include "tessera/core/assert.hpp"

namespace tessera {

namespace {

[[nodiscard]] MemoryState from_native_state(DWORD state) noexcept {
    switch (state) {
        case MEM_COMMIT:  return MemoryState::Committed;
        case MEM_RESERVE: return MemoryState::Reserved;
        default:          return MemoryState::Free;
    }
}

[[nodiscard]] MemoryType from_native_type(DWORD type) noexcept {
    switch (type) {
        case MEM_IMAGE:   return MemoryType::Image;
        case MEM_MAPPED:  return MemoryType::Mapped;
        case MEM_PRIVATE: return MemoryType::Private;
        default:          return MemoryType::Unknown;
    }
}

[[nodiscard]] MemoryProtection from_native_protect(DWORD protect) noexcept {
    MemoryProtection out = MemoryProtection::None;
    const DWORD base = protect & 0xFFu;
    switch (base) {
        case PAGE_NOACCESS:          out |= MemoryProtection::NoAccess; break;
        case PAGE_READONLY:          out |= MemoryProtection::Read; break;
        case PAGE_READWRITE:         out |= MemoryProtection::ReadWrite; break;
        case PAGE_WRITECOPY:         out |= MemoryProtection::Read | MemoryProtection::CopyOnWrite; break;
        case PAGE_EXECUTE:           out |= MemoryProtection::Execute; break;
        case PAGE_EXECUTE_READ:      out |= MemoryProtection::ExecuteRead; break;
        case PAGE_EXECUTE_READWRITE: out |= MemoryProtection::ExecuteReadWrite; break;
        case PAGE_EXECUTE_WRITECOPY: out |= MemoryProtection::ExecuteWriteCopy; break;
        default: break;
    }
    if ((protect & PAGE_GUARD) != 0) {
        out |= MemoryProtection::Guard;
    }
    if ((protect & PAGE_NOCACHE) != 0) {
        out |= MemoryProtection::NoCache;
    }
    if ((protect & PAGE_WRITECOMBINE) != 0) {
        out |= MemoryProtection::WriteCombine;
    }
    return out;
}

[[nodiscard]] DWORD to_native_protect(MemoryProtection protect) noexcept {
    const bool exec = has_flag(protect, MemoryProtection::Execute);
    const bool write = has_flag(protect, MemoryProtection::Write);
    const bool cow = has_flag(protect, MemoryProtection::CopyOnWrite);
    const bool read = has_flag(protect, MemoryProtection::Read);

    DWORD out = PAGE_NOACCESS;
    if (exec) {
        if (write) {
            out = PAGE_EXECUTE_READWRITE;
        } else if (cow) {
            out = PAGE_EXECUTE_WRITECOPY;
        } else if (read) {
            out = PAGE_EXECUTE_READ;
        } else {
            out = PAGE_EXECUTE;
        }
    } else {
        if (write) {
            out = PAGE_READWRITE;
        } else if (cow) {
            out = PAGE_WRITECOPY;
        } else if (read) {
            out = PAGE_READONLY;
        } else {
            out = PAGE_NOACCESS;
        }
    }

    if (has_flag(protect, MemoryProtection::Guard)) {
        out |= PAGE_GUARD;
    }
    if (has_flag(protect, MemoryProtection::NoCache)) {
        out |= PAGE_NOCACHE;
    }
    if (has_flag(protect, MemoryProtection::WriteCombine)) {
        out |= PAGE_WRITECOMBINE;
    }
    return out;
}

class WindowsMemoryBackend final : public IMemoryBackend {
public:
    explicit WindowsMemoryBackend(HANDLE handle) noexcept : handle_(handle) {}

    [[nodiscard]] Result<std::size_t> read(Address address,
                                           std::span<std::byte> buffer) const override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        if (address.is_null()) {
            return fail(ErrorCode::NullAddress, "ReadProcessMemory");
        }
        if constexpr (sizeof(void*) == 4) {
            if (address.value() > (std::numeric_limits<std::uintptr_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "ReadProcessMemory");
            }
        }

        SIZE_T bytes_read = 0;
        const BOOL ok_flag = ::ReadProcessMemory(
            handle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address.value())),
            buffer.data(),
            buffer.size(),
            &bytes_read);

        if (bytes_read > 0) {
            return static_cast<std::size_t>(bytes_read);
        }
        if (!ok_flag) {
            const DWORD err = ::GetLastError();
            return fail(err == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::PartialTransfer,
                        "ReadProcessMemory",
                        err);
        }
        return std::size_t{0};
    }

    [[nodiscard]] Result<std::size_t> write(Address address,
                                            std::span<const std::byte> data) const override {
        if (data.empty()) {
            return std::size_t{0};
        }
        if (address.is_null()) {
            return fail(ErrorCode::NullAddress, "WriteProcessMemory");
        }
        if constexpr (sizeof(void*) == 4) {
            if (address.value() > (std::numeric_limits<std::uintptr_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "WriteProcessMemory");
            }
        }

        SIZE_T bytes_written = 0;
        const BOOL ok_flag = ::WriteProcessMemory(
            handle_,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address.value())),
            data.data(),
            data.size(),
            &bytes_written);

        if (bytes_written > 0) {
            return static_cast<std::size_t>(bytes_written);
        }
        if (!ok_flag) {
            const DWORD err = ::GetLastError();
            return fail(err == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::PartialTransfer,
                        "WriteProcessMemory",
                        err);
        }
        return std::size_t{0};
    }

    [[nodiscard]] Result<MemoryRegionInfo> query(Address address) const override {
        if constexpr (sizeof(void*) == 4) {
            if (address.value() > (std::numeric_limits<std::uintptr_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "VirtualQueryEx");
            }
        }

        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T got = ::VirtualQueryEx(
            handle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address.value())),
            &mbi,
            sizeof(mbi));

        if (got != sizeof(mbi)) {
            const DWORD err = ::GetLastError();
            return fail(ErrorCode::OutOfRange, "VirtualQueryEx", err);
        }

        return MemoryRegionInfo{
            .base = Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress))},
            .allocation_base =
                Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mbi.AllocationBase))},
            .size = static_cast<std::uint64_t>(mbi.RegionSize),
            .state = from_native_state(mbi.State),
            .protection = from_native_protect(mbi.Protect),
            .allocation_protection = from_native_protect(mbi.AllocationProtect),
            .type = from_native_type(mbi.Type),
        };
    }

    [[nodiscard]] Result<MemoryProtection> protect(Address address,
                                                   std::uint64_t size,
                                                   MemoryProtection new_protection) const override {
        if (address.is_null() || size == 0) {
            return fail(ErrorCode::InvalidArgument, "VirtualProtectEx");
        }
        if constexpr (sizeof(void*) == 4) {
            if (address.value() > (std::numeric_limits<std::uintptr_t>::max)() ||
                size > (std::numeric_limits<std::size_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "VirtualProtectEx");
            }
        }

        DWORD old_protect = 0;
        const BOOL ok_flag = ::VirtualProtectEx(
            handle_,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address.value())),
            static_cast<SIZE_T>(size),
            to_native_protect(new_protection),
            &old_protect);

        if (!ok_flag) {
            return fail(ErrorCode::ProtectionFailed, "VirtualProtectEx", ::GetLastError());
        }
        return from_native_protect(old_protect);
    }

    [[nodiscard]] Status flush_instruction_cache(AddressRange range) const override {
        if (range.empty()) {
            return ok();
        }
        if constexpr (sizeof(void*) == 4) {
            if (range.begin().value() > (std::numeric_limits<std::uintptr_t>::max)() ||
                range.size() > (std::numeric_limits<std::size_t>::max)()) {
                return fail(ErrorCode::OutOfRange, "FlushInstructionCache");
            }
        }
        if (!::FlushInstructionCache(
                handle_,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(range.begin().value())),
                static_cast<SIZE_T>(range.size()))) {
            return fail(ErrorCode::IoError, "FlushInstructionCache", ::GetLastError());
        }
        return ok();
    }

private:
    HANDLE handle_ = nullptr;
};

} // namespace

const IMemoryBackend& memory_backend(const Process& process) noexcept {
    const auto& st = process.state();
    TESSERA_ASSERT(st != nullptr);
    if (!st->backend) {
        st->backend = std::make_shared<WindowsMemoryBackend>(static_cast<HANDLE>(st->handle));
    }
    return *st->backend;
}

} // namespace tessera
