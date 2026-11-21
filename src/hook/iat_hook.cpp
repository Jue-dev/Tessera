#include "tessera/hook/iat_hook.hpp"

#include "tessera/memory/memory_backend.hpp"
#include "tessera/memory/memory_reader.hpp"
#include "tessera/memory/protection_scope.hpp"
#include "tessera/module/pe_image.hpp"

#include <array>
#include <cctype>
#include <cstring>
#include <utility>

namespace tessera {
namespace {

bool equal_ascii_case_insensitive(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    for (std::size_t i = 0; i < lhs.size(); ++i) {
        const auto left = std::tolower(static_cast<unsigned char>(lhs[i]));
        const auto right = std::tolower(static_cast<unsigned char>(rhs[i]));
        if (left != right) {
            return false;
        }
    }
    return true;
}

Status write_pointer(const Process& process, Address slot, Address value) {
    std::array<std::byte, 8> bytes{};
    const auto pointer_size = process.pointer_size();
    const std::uint64_t raw = value.value();
    std::memcpy(bytes.data(), &raw, pointer_size);

    auto written =
        memory_backend(process).write(slot, std::span<const std::byte>{bytes.data(), pointer_size});
    if (!written) {
        return std::unexpected(written.error());
    }
    if (*written != pointer_size) {
        return fail(ErrorCode::PartialTransfer, "IatHook::write_pointer");
    }

    // An IAT slot is data, not executable code, so no instruction-cache flush
    // is necessary after changing the pointer.
    return ok();
}

} // namespace

IatHook::IatHook(IatHook&& other) noexcept
    : process_(std::move(other.process_)), slot_(std::exchange(other.slot_, Address{})),
      original_(std::exchange(other.original_, Address{})),
      replacement_(std::exchange(other.replacement_, Address{})),
      installed_(std::exchange(other.installed_, false)) {}

IatHook::~IatHook() noexcept {
    if (installed_) {
        (void)restore();
    }
}

Result<IatHook> IatHook::install(const Process& process, Address module_base,
                                 std::string_view imported_module, std::string_view function_name,
                                 Address replacement) {
    if (module_base.is_null() || replacement.is_null() || imported_module.empty() || function_name.empty() ||
        (process.pointer_size() != 4 && process.pointer_size() != 8) ||
        (process.pointer_size() == 4 && replacement.value() > 0xffffffffULL)) {
        return fail(ErrorCode::InvalidArgument, "IatHook::install");
    }

    auto image = PeImage::from_memory(process, module_base);
    if (!image) {
        return std::unexpected(image.error());
    }

    const ImportEntry* found = nullptr;
    for (const auto& entry : image->imports()) {
        if (!entry.by_ordinal && equal_ascii_case_insensitive(entry.module_name, imported_module) &&
            entry.function_name == function_name) {
            found = &entry;
            break;
        }
    }
    if (found == nullptr) {
        return fail(ErrorCode::NotFound, "IatHook::install", 0,
                    "Requested DLL/function import was not found");
    }

    auto slot = module_base.add_rva(found->iat_rva);
    if (!slot) {
        return std::unexpected(slot.error());
    }

    MemoryReader reader{process};
    auto original = reader.read_pointer(*slot);
    if (!original) {
        return std::unexpected(original.error());
    }
    if (*original == replacement) {
        return fail(ErrorCode::Conflict, "IatHook::install", 0,
                    "IAT slot already contains the replacement address");
    }

    auto protection = ProtectionScope::create(process, AddressRange{*slot, process.pointer_size()},
                                              MemoryProtection::Read | MemoryProtection::Write);
    if (!protection) {
        return std::unexpected(protection.error());
    }

    auto written = write_pointer(process, *slot, replacement);
    if (!written) {
        // A short write can leave a torn pointer. Restore the saved value
        // while the page is still writable, then restore its protection.
        (void)write_pointer(process, *slot, *original);
        (void)protection->restore();
        return std::unexpected(written.error());
    }

    auto restored = protection->restore();
    if (!restored) {
        auto rollback_protection =
            ProtectionScope::create(process, AddressRange{*slot, process.pointer_size()},
                                    MemoryProtection::Read | MemoryProtection::Write);
        if (rollback_protection) {
            (void)write_pointer(process, *slot, *original);
            (void)rollback_protection->restore();
        } else {
            (void)write_pointer(process, *slot, *original);
        }
        (void)protection->restore();
        return std::unexpected(restored.error());
    }

    return IatHook{process, *slot, *original, replacement};
}

Status IatHook::restore() noexcept {
    if (!installed_) {
        return ok();
    }

    MemoryReader reader{process_};
    auto current = reader.read_pointer(slot_);
    if (!current) {
        return std::unexpected(current.error());
    }
    if (*current != replacement_) {
        return fail(ErrorCode::Conflict, "IatHook::restore", 0,
                    "IAT slot no longer contains the address installed by this hook");
    }

    auto protection = ProtectionScope::create(process_, AddressRange{slot_, process_.pointer_size()},
                                              MemoryProtection::Read | MemoryProtection::Write);
    if (!protection) {
        return std::unexpected(protection.error());
    }

    auto written = write_pointer(process_, slot_, original_);
    if (!written) {
        (void)write_pointer(process_, slot_, original_);
        (void)protection->restore();
        return written;
    }

    installed_ = false;
    auto restored = protection->restore();
    if (!restored) {
        (void)protection->restore();
        return restored;
    }

    return ok();
}

} // namespace tessera
