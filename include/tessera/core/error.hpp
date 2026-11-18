#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace tessera {

enum class ErrorCode : std::uint32_t {
    InvalidArgument,
    NullAddress,
    AddressOverflow,
    OutOfRange,
    OutOfMemory,
    AccessDenied,
    ProcessNotFound,
    ProcessExited,
    UnsupportedArchitecture,
    UnsupportedInstruction,
    BackendUnavailable,
    PartialTransfer,
    ProtectionFailed,
    ProtectionRestoreFailed,
    InvalidPattern,
    InvalidPe,
    NotFound,
    Ambiguous,
    ThreadEnumerationFailed,
    Timeout,
    Cancelled,
    IoError,
    ParseError,
    ValidationFailed,
    Conflict,
};

struct [[nodiscard]] Error {
    ErrorCode code = ErrorCode::InvalidArgument;
    std::uint32_t native = 0;
    std::string_view operation{};
    std::string detail{};

    [[nodiscard]] friend bool operator==(const Error& lhs, const Error& rhs) noexcept {
        return lhs.code == rhs.code && lhs.native == rhs.native &&
               lhs.operation == rhs.operation && lhs.detail == rhs.detail;
    }
};

[[nodiscard]] constexpr std::string_view error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::InvalidArgument:         return "InvalidArgument";
        case ErrorCode::NullAddress:             return "NullAddress";
        case ErrorCode::AddressOverflow:         return "AddressOverflow";
        case ErrorCode::OutOfRange:              return "OutOfRange";
        case ErrorCode::OutOfMemory:             return "OutOfMemory";
        case ErrorCode::AccessDenied:            return "AccessDenied";
        case ErrorCode::ProcessNotFound:         return "ProcessNotFound";
        case ErrorCode::ProcessExited:           return "ProcessExited";
        case ErrorCode::UnsupportedArchitecture: return "UnsupportedArchitecture";
        case ErrorCode::UnsupportedInstruction:  return "UnsupportedInstruction";
        case ErrorCode::BackendUnavailable:      return "BackendUnavailable";
        case ErrorCode::PartialTransfer:         return "PartialTransfer";
        case ErrorCode::ProtectionFailed:        return "ProtectionFailed";
        case ErrorCode::ProtectionRestoreFailed: return "ProtectionRestoreFailed";
        case ErrorCode::InvalidPattern:          return "InvalidPattern";
        case ErrorCode::InvalidPe:               return "InvalidPe";
        case ErrorCode::NotFound:                return "NotFound";
        case ErrorCode::Ambiguous:               return "Ambiguous";
        case ErrorCode::ThreadEnumerationFailed: return "ThreadEnumerationFailed";
        case ErrorCode::Timeout:                 return "Timeout";
        case ErrorCode::Cancelled:               return "Cancelled";
        case ErrorCode::IoError:                 return "IoError";
        case ErrorCode::ParseError:              return "ParseError";
        case ErrorCode::ValidationFailed:        return "ValidationFailed";
        case ErrorCode::Conflict:                return "Conflict";
    }
    return "Unknown";
}

// Keep the common literal-message path separate from the owning-string path.
// Besides avoiding an otherwise unnecessary temporary allocation, this keeps
// GCC 14.2 -fanalyzer from mis-tracking libstdc++ basic_string SSO internals
// when a default/empty std::string is moved through Error construction.
[[nodiscard]] inline Error make_error(ErrorCode code,
                                      std::string_view operation = {},
                                      std::uint32_t native = 0,
                                      const char* detail = "") {
    Error error{};
    error.code = code;
    error.native = native;
    error.operation = operation;
    if (detail != nullptr) {
        error.detail.assign(detail);
    }
    return error;
}

// Owning overload for dynamically produced diagnostics (e.g. parser messages).
[[nodiscard]] inline Error make_error(ErrorCode code,
                                      std::string_view operation,
                                      std::uint32_t native,
                                      std::string detail) {
    Error error{};
    error.code = code;
    error.native = native;
    error.operation = operation;
    error.detail = std::move(detail);
    return error;
}

} // namespace tessera
