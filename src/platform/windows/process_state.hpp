#pragma once

#include <memory>

#include "tessera/diagnostics/diagnostic_observer.hpp"
#include "tessera/process/process.hpp"

namespace tessera::detail {

struct ProcessState {
    void* handle = nullptr;
    Ownership ownership = Ownership::Borrowed;
    ProcessInfo info{};
    DiagnosticObserver* observer = nullptr;
    std::shared_ptr<IMemoryBackend> backend{};

    ProcessState() noexcept = default;
    ~ProcessState() noexcept;

    ProcessState(const ProcessState&) = delete;
    ProcessState& operator=(const ProcessState&) = delete;
};

} // namespace tessera::detail
