#include "tessera/diagnostics/diagnostics.hpp"

#include <Windows.h>

#include <format>
#include <string>

#if !defined(NDEBUG) && defined(__cpp_lib_stacktrace) && __cpp_lib_stacktrace >= 202011L
    #include <stacktrace>
    #define TESSERA_HAS_STD_STACKTRACE 1
#else
    #define TESSERA_HAS_STD_STACKTRACE 0
#endif

namespace tessera::diagnostics {

std::string format_native_error(std::uint32_t native_code) {
    if (native_code == 0) {
        return {};
    }

    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD len = ::FormatMessageW(
        flags,
        nullptr,
        static_cast<DWORD>(native_code),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (len == 0 || buffer == nullptr) {
        return std::format("win32 error {}", native_code);
    }

    std::wstring wmsg(buffer, len);
    ::LocalFree(buffer);

    while (!wmsg.empty() && (wmsg.back() == L'\r' || wmsg.back() == L'\n' || wmsg.back() == L' ')) {
        wmsg.pop_back();
    }

    if (wmsg.empty()) {
        return std::format("win32 error {}", native_code);
    }

    const int utf8_len = ::WideCharToMultiByte(
        CP_UTF8, 0, wmsg.data(), static_cast<int>(wmsg.size()), nullptr, 0, nullptr, nullptr);
    if (utf8_len <= 0) {
        return std::format("win32 error {}", native_code);
    }

    std::string out(static_cast<std::size_t>(utf8_len), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wmsg.data(), static_cast<int>(wmsg.size()), out.data(), utf8_len, nullptr, nullptr);
    return out;
}

std::string describe(const Error& err) {
    std::string result = std::string(error_code_name(err.code));
    if (!err.operation.empty()) {
        result += std::format(" in {}", err.operation);
    }
    if (err.native != 0) {
        const std::string sys_msg = format_native_error(err.native);
        if (!sys_msg.empty()) {
            result += std::format(" [native={} ({})]", err.native, sys_msg);
        } else {
            result += std::format(" [native={}]", err.native);
        }
    }
    if (!err.detail.empty()) {
        result += std::format(": {}", err.detail);
    }
    return result;
}

std::string format_address(Address addr, std::uint8_t pointer_size) {
    if (pointer_size == 4) {
        return std::format("0x{:08X}", static_cast<std::uint32_t>(addr.value() & 0xFFFFFFFFULL));
    }
    return std::format("0x{:016X}", addr.value());
}

std::string capture_debug_stacktrace([[maybe_unused]] std::size_t skip_frames) {
#if TESSERA_HAS_STD_STACKTRACE
    try {
        return std::to_string(std::stacktrace::current(skip_frames));
    } catch (...) {
        return {};
    }
#else
    return {};
#endif
}

} // namespace tessera::diagnostics
