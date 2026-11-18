#pragma once

#include <cstdint>
#include <memory>

#include "tessera/core/enum_flags.hpp"
#include "tessera/core/result.hpp"
#include "tessera/core/types.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"

namespace tessera {

class IMemoryBackend;

namespace detail {
struct ProcessState;
} // namespace detail

enum class Architecture : std::uint8_t {
    X86,
    X64,
};

enum class ProcessAccess : std::uint32_t {
    None = 0,
    Query = 1u << 0,
    Read = 1u << 1,
    Write = 1u << 2,
    Operation = 1u << 3,
    ReadQuery = Query | Read,
    ReadWriteQuery = Query | Read | Write | Operation,
};

} // namespace tessera

TESSERA_ENABLE_ENUM_FLAGS(tessera::ProcessAccess);

namespace tessera {

struct ProcessInfo {
    ProcessId pid{};
    Architecture architecture = (sizeof(void*) == 8) ? Architecture::X64 : Architecture::X86;
    std::uint8_t pointer_size = static_cast<std::uint8_t>(sizeof(void*));
    bool is_local = false;
    ProcessAccess granted_access = ProcessAccess::ReadWriteQuery;
    std::uint64_t max_application_address = (sizeof(void*) == 8) ? 0x7FFFFFFEFFFFULL : 0x7FFEFFFFULL;
};

struct ProcessOpenOptions {
    ProcessAccess access = ProcessAccess::ReadWriteQuery;
    DiagnosticObserver* observer = nullptr;
};

// Thread-safety: const member functions are re-entrant. Copying shares ownership of the underlying process state.
class Process {
public:
    [[nodiscard]] static Process current(DiagnosticObserver* observer = nullptr) noexcept;

    [[nodiscard]] static Result<Process> open(ProcessId pid,
                                              ProcessAccess access = ProcessAccess::ReadWriteQuery,
                                              DiagnosticObserver* observer = nullptr);

    [[nodiscard]] static Result<Process> open(ProcessId pid, const ProcessOpenOptions& options);

    [[nodiscard]] static Result<Process> from_backend(ProcessInfo info,
                                                      std::shared_ptr<IMemoryBackend> backend,
                                                      DiagnosticObserver* observer = nullptr);

    [[nodiscard]] const ProcessInfo& info() const noexcept;
    [[nodiscard]] ProcessId pid() const noexcept { return info().pid; }
    [[nodiscard]] Architecture architecture() const noexcept { return info().architecture; }
    [[nodiscard]] std::uint8_t pointer_size() const noexcept { return info().pointer_size; }
    [[nodiscard]] bool is_local() const noexcept { return info().is_local; }
    [[nodiscard]] DiagnosticObserver* observer() const noexcept;

    [[nodiscard]] Result<bool> is_alive() const noexcept;

    [[nodiscard]] const std::shared_ptr<detail::ProcessState>& state() const noexcept { return state_; }
    explicit Process(std::shared_ptr<detail::ProcessState> state) noexcept;

    [[nodiscard]] friend bool operator==(const Process& lhs, const Process& rhs) noexcept {
        return lhs.state_ == rhs.state_ || lhs.pid() == rhs.pid();
    }

private:
    std::shared_ptr<detail::ProcessState> state_;
};

} // namespace tessera
