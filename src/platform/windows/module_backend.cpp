#include "tessera/module/module.hpp"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <new>
#include <limits>
#include <thread>

#include "platform/windows/process_state.hpp"
#include "tessera/core/assert.hpp"

namespace tessera {

namespace {

[[nodiscard]] bool equals_ordinal_ignore_case(std::u16string_view a, std::u16string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return ::CompareStringOrdinal(reinterpret_cast<LPCWCH>(a.data()),
                                  static_cast<int>(a.size()),
                                  reinterpret_cast<LPCWCH>(b.data()),
                                  static_cast<int>(b.size()),
                                  TRUE) == CSTR_EQUAL;
}

[[nodiscard]] Result<std::vector<HMODULE>> enumerate_native_modules(HANDLE proc_handle) {
    try {
        std::vector<HMODULE> handles(256);
        DWORD needed = 0;
        for (int attempt = 0; attempt < 5; ++attempt) {
            if (handles.size() > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()) / sizeof(HMODULE)) {
                return fail(ErrorCode::OutOfRange,
                            "EnumProcessModulesEx",
                            0,
                            "Module enumeration buffer exceeds the Win32 DWORD size limit");
            }

            const auto buf_bytes = static_cast<DWORD>(handles.size() * sizeof(HMODULE));
            if (!::EnumProcessModulesEx(proc_handle, handles.data(), buf_bytes, &needed, LIST_MODULES_ALL)) {
                const DWORD err = ::GetLastError();
                return fail(err == ERROR_ACCESS_DENIED ? ErrorCode::AccessDenied : ErrorCode::IoError,
                            "EnumProcessModulesEx",
                            err);
            }
            if (needed % sizeof(HMODULE) != 0) {
                return fail(ErrorCode::PartialTransfer,
                            "EnumProcessModulesEx",
                            0,
                            "The module byte count is not aligned to the HMODULE size");
            }
            if (needed <= buf_bytes) {
                handles.resize(needed / sizeof(HMODULE));
                return handles;
            }

            if (attempt == 4) {
                return fail(ErrorCode::PartialTransfer,
                            "EnumProcessModulesEx",
                            0,
                            "The module list kept growing; refusing to return a truncated snapshot");
            }

            const std::size_t required_count = static_cast<std::size_t>(needed / sizeof(HMODULE));
            if (required_count > handles.max_size() - 32) {
                return fail(ErrorCode::OutOfRange,
                            "EnumProcessModulesEx",
                            0,
                            "The required module list exceeds the vector capacity limit");
            }
            handles.resize(required_count + 32);
        }
        return fail(ErrorCode::PartialTransfer, "EnumProcessModulesEx");
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "EnumProcessModulesEx");
    }
}

[[nodiscard]] Result<Module> build_module_from_handle(const Process& process,
                                                      HANDLE proc_handle,
                                                      HMODULE mod_handle) {
    MODULEINFO mi{};
    if (!::GetModuleInformation(proc_handle, mod_handle, &mi, sizeof(mi)) || mi.SizeOfImage == 0) {
        return fail(ErrorCode::IoError, "GetModuleInformation", ::GetLastError());
    }

    wchar_t base_name_buf[MAX_PATH]{};
    const DWORD base_len = ::GetModuleBaseNameW(proc_handle, mod_handle, base_name_buf, MAX_PATH);
    if (base_len == 0) {
        return fail(ErrorCode::IoError, "GetModuleBaseNameW", ::GetLastError());
    }

    constexpr DWORD full_path_capacity = static_cast<DWORD>(MAX_PATH * 2);
    wchar_t full_path_buf[full_path_capacity]{};
    const DWORD full_len =
        ::GetModuleFileNameExW(proc_handle, mod_handle, full_path_buf, full_path_capacity);
    if (full_len >= full_path_capacity) {
        return fail(ErrorCode::PartialTransfer, "GetModuleFileNameExW", ERROR_INSUFFICIENT_BUFFER);
    }

    try {
        std::u16string name_u16(reinterpret_cast<const char16_t*>(base_name_buf), base_len);
        std::u16string path_u16;
        if (full_len > 0) {
            path_u16.assign(reinterpret_cast<const char16_t*>(full_path_buf), full_len);
        }
        const auto base_addr =
            Address{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll))};
        return Module{process,
                      std::move(name_u16),
                      std::move(path_u16),
                      AddressRange{base_addr, static_cast<std::uint64_t>(mi.SizeOfImage)}};
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "build_module_from_handle");
    }
}

} // namespace

Result<std::vector<Module>> ModuleCatalog::snapshot(const Process& process) {
    const auto& st = process.state();
    TESSERA_ASSERT(st != nullptr);
    if (st->handle == nullptr) {
        return fail(ErrorCode::BackendUnavailable,
                    "ModuleCatalog::snapshot",
                    0,
                    "Process has no native OS handle");
    }
    const auto proc_handle = static_cast<HANDLE>(st->handle);
    auto handles = enumerate_native_modules(proc_handle);
    if (!handles) {
        return std::unexpected(handles.error());
    }

    try {
        std::vector<Module> modules;
        modules.reserve(handles->size());
        for (const HMODULE h : *handles) {
            if (auto m = build_module_from_handle(process, proc_handle, h)) {
                modules.push_back(std::move(*m));
            }
        }
        return modules;
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "ModuleCatalog::snapshot");
    }
}

Result<Module> ModuleCatalog::main_module(const Process& process) {
    const auto& st = process.state();
    TESSERA_ASSERT(st != nullptr);
    if (st->handle == nullptr) {
        return fail(ErrorCode::BackendUnavailable,
                    "ModuleCatalog::main_module",
                    0,
                    "Process has no native OS handle");
    }
    const auto proc_handle = static_cast<HANDLE>(st->handle);
    if (process.is_local()) {
        const HMODULE main_h = ::GetModuleHandleW(nullptr);
        if (main_h == nullptr) {
            return fail(ErrorCode::NotFound, "GetModuleHandleW", ::GetLastError());
        }
        return build_module_from_handle(process, proc_handle, main_h);
    }

    auto mods = snapshot(process);
    if (!mods) {
        return std::unexpected(mods.error());
    }
    if (mods->empty()) {
        return fail(ErrorCode::NotFound, "ModuleCatalog::main_module");
    }
    return std::move(mods->front());
}

Result<Module> ModuleCatalog::find(const Process& process, std::u16string_view name) {
    if (name.empty()) {
        return fail(ErrorCode::InvalidArgument,
                    "ModuleCatalog::find",
                    0,
                    "Module name cannot be empty (use main_module() for main executable)");
    }
    auto mods = snapshot(process);
    if (!mods) {
        return std::unexpected(mods.error());
    }
    for (auto& m : *mods) {
        if (equals_ordinal_ignore_case(m.name(), name)) {
            return std::move(m);
        }
    }
    return fail(ErrorCode::NotFound, "ModuleCatalog::find");
}

Result<Module> ModuleCatalog::containing(const Process& process, Address address) {
    if (address.is_null()) {
        return fail(ErrorCode::NullAddress, "ModuleCatalog::containing");
    }
    auto mods = snapshot(process);
    if (!mods) {
        return std::unexpected(mods.error());
    }
    for (auto& m : *mods) {
        if (m.range().contains(address)) {
            return std::move(m);
        }
    }
    return fail(ErrorCode::NotFound, "ModuleCatalog::containing");
}

Result<Module> ModuleCatalog::wait_for(const Process& process,
                                       std::u16string_view name,
                                       std::chrono::milliseconds timeout,
                                       std::stop_token stop,
                                       std::chrono::milliseconds poll_interval) {
    if (name.empty()) {
        return fail(ErrorCode::InvalidArgument, "ModuleCatalog::wait_for");
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    const auto sleep_dur = (std::max)(poll_interval, std::chrono::milliseconds{1});

    for (;;) {
        if (stop.stop_requested()) {
            return fail(ErrorCode::Cancelled, "ModuleCatalog::wait_for");
        }
        auto found = find(process, name);
        if (found) {
            return found;
        }
        if (found.error().code != ErrorCode::NotFound) {
            return found;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return fail(ErrorCode::Timeout, "ModuleCatalog::wait_for");
        }
        std::this_thread::sleep_for(sleep_dur);
    }
}

} // namespace tessera
