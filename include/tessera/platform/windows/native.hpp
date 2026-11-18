#pragma once

#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"
#include "tessera/process/process.hpp"

namespace tessera::platform::windows {

using NativeHandle = void*;

[[nodiscard]] Result<Process> from_native_handle(
    NativeHandle handle,
    Ownership ownership,
    ProcessAccess granted_access = ProcessAccess::ReadWriteQuery,
    DiagnosticObserver* observer = nullptr);

[[nodiscard]] NativeHandle native_handle(const Process& process) noexcept;

} // namespace tessera::platform::windows
