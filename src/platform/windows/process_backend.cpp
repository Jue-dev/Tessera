#include "platform/windows/process_state.hpp"
#include "tessera/core/assert.hpp"
#include "tessera/platform/windows/native.hpp"

#include <Windows.h>
#include <new>

namespace tessera::detail {

ProcessState::~ProcessState() noexcept {
    if (ownership == Ownership::Owned && handle != nullptr && handle != ::GetCurrentProcess()) {
        ::CloseHandle(static_cast<HANDLE>(handle));
        handle = nullptr;
    }
}

} // namespace tessera::detail

namespace tessera {

namespace {

[[nodiscard]] DWORD to_native_access(ProcessAccess access) noexcept {
    DWORD flags = 0;
    if (has_flag(access, ProcessAccess::Query)) {
        flags |= PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
    }
    if (has_flag(access, ProcessAccess::Read)) {
        flags |= PROCESS_VM_READ;
    }
    if (has_flag(access, ProcessAccess::Write)) {
        flags |= PROCESS_VM_WRITE;
    }
    if (has_flag(access, ProcessAccess::Operation)) {
        flags |= PROCESS_VM_OPERATION;
    }
    return flags;
}

[[nodiscard]] std::uint64_t query_native_max_app_address(Architecture target_arch) noexcept {
    SYSTEM_INFO si{};
    ::GetNativeSystemInfo(&si);
    const auto host_max =
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress));
    if (target_arch == Architecture::X86) {
        // On 64-bit Windows, WOW64 processes can address up to 4 GiB (0xFFEFFFFF); on 32-bit OS, host_max.
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            return 0xFFEFFFFFULL;
        }
        return host_max < 0xFFEFFFFFULL ? host_max : 0xFFEFFFFFULL;
    }
    return host_max;
}

[[nodiscard]] Result<Architecture> detect_target_architecture(HANDLE process_handle) noexcept {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!::IsWow64Process2(process_handle, &process_machine, &native_machine)) {
        const DWORD err = ::GetLastError();
        return fail(ErrorCode::AccessDenied, "IsWow64Process2", err, "Failed to query process architecture");
    }

    if (native_machine != IMAGE_FILE_MACHINE_AMD64 && native_machine != IMAGE_FILE_MACHINE_I386) {
        return fail(ErrorCode::UnsupportedArchitecture, "IsWow64Process2", 0,
                    "Unsupported host OS architecture (only x86 and x64 are supported)");
    }

    Architecture target_arch = Architecture::X64;
    if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN) {
        // Process is not running under WOW64; its architecture matches the native OS architecture.
        target_arch = (native_machine == IMAGE_FILE_MACHINE_AMD64) ? Architecture::X64 : Architecture::X86;
    } else if (process_machine == IMAGE_FILE_MACHINE_I386) {
        target_arch = Architecture::X86;
    } else {
        return fail(ErrorCode::UnsupportedArchitecture, "IsWow64Process2", 0,
                    "Unsupported target process machine type");
    }

    if constexpr (sizeof(void*) == 4) {
        if (target_arch == Architecture::X64) {
            return fail(ErrorCode::UnsupportedArchitecture, "Process::open", 0,
                        "32-bit Tessera build cannot attach to a native 64-bit target process");
        }
    }

    return target_arch;
}

[[nodiscard]] ErrorCode map_win32_open_error(DWORD err) noexcept {
    switch (err) {
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
        return ErrorCode::AccessDenied;
    case ERROR_INVALID_PARAMETER:
    case ERROR_NOT_FOUND:
        return ErrorCode::ProcessNotFound;
    default:
        return ErrorCode::InvalidArgument;
    }
}

} // namespace

Process::Process(std::shared_ptr<detail::ProcessState> state) noexcept : state_(std::move(state)) {
    TESSERA_ASSERT(state_ != nullptr);
}

Process Process::current(DiagnosticObserver* observer) noexcept {
    if (observer == nullptr) {
        static const std::shared_ptr<detail::ProcessState> kCurrentState = [] {
            auto st = std::make_shared<detail::ProcessState>();
            st->handle = ::GetCurrentProcess();
            st->ownership = Ownership::Borrowed;
            constexpr Architecture kArch = (sizeof(void*) == 8) ? Architecture::X64 : Architecture::X86;
            st->info = ProcessInfo{
                .pid = ProcessId{::GetCurrentProcessId()},
                .architecture = kArch,
                .pointer_size = static_cast<std::uint8_t>(sizeof(void*)),
                .is_local = true,
                .granted_access = ProcessAccess::ReadWriteQuery,
                .max_application_address = query_native_max_app_address(kArch),
            };
            st->observer = nullptr;
            return st;
        }();
        return Process{kCurrentState};
    }

    auto st = std::make_shared<detail::ProcessState>();
    st->handle = ::GetCurrentProcess();
    st->ownership = Ownership::Borrowed;
    constexpr Architecture kArch = (sizeof(void*) == 8) ? Architecture::X64 : Architecture::X86;
    st->info = ProcessInfo{
        .pid = ProcessId{::GetCurrentProcessId()},
        .architecture = kArch,
        .pointer_size = static_cast<std::uint8_t>(sizeof(void*)),
        .is_local = true,
        .granted_access = ProcessAccess::ReadWriteQuery,
        .max_application_address = query_native_max_app_address(kArch),
    };
    st->observer = observer;
    return Process{std::move(st)};
}

Result<Process> Process::open(ProcessId pid, ProcessAccess access, DiagnosticObserver* observer) {
    return open(pid, ProcessOpenOptions{.access = access, .observer = observer});
}

Result<Process> Process::open(ProcessId pid, const ProcessOpenOptions& options) {
    if (!pid.valid()) {
        return fail(ErrorCode::InvalidArgument, "Process::open", 0, "PID cannot be zero");
    }
    if (options.access == ProcessAccess::None) {
        return fail(ErrorCode::InvalidArgument, "Process::open", 0, "Access mask cannot be empty");
    }

    // IsWow64Process2 requires at least PROCESS_QUERY_LIMITED_INFORMATION
    const DWORD native_access = to_native_access(options.access) | PROCESS_QUERY_LIMITED_INFORMATION;
    const HANDLE h = ::OpenProcess(native_access, FALSE, pid.value());
    if (h == nullptr) {
        const DWORD err = ::GetLastError();
        auto error = make_error(map_win32_open_error(err), "OpenProcess", err);
        diagnostics::notify(options.observer, DiagnosticSeverity::Error, "Process", "OpenProcess failed",
                            error);
        return std::unexpected(std::move(error));
    }

    return platform::windows::from_native_handle(h, Ownership::Owned, options.access, options.observer);
}

Result<Process> Process::from_backend(ProcessInfo info, std::shared_ptr<IMemoryBackend> backend,
                                      DiagnosticObserver* observer) {
    if (!backend) {
        return fail(ErrorCode::InvalidArgument, "Process::from_backend", 0, "Backend cannot be null");
    }
    if (!info.pid.valid()) {
        return fail(ErrorCode::InvalidArgument, "Process::from_backend", 0, "PID cannot be zero");
    }
    if (info.pointer_size != 4 && info.pointer_size != 8) {
        return fail(ErrorCode::InvalidArgument, "Process::from_backend", 0,
                    "Pointer size must be 4 or 8 bytes");
    }

    try {
        auto st = std::make_shared<detail::ProcessState>();
        st->handle = nullptr;
        st->ownership = Ownership::Borrowed;
        st->info = info;
        st->observer = observer;
        st->backend.store(std::move(backend), std::memory_order_release);
        return Process{std::move(st)};
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "Process::from_backend");
    }
}

const ProcessInfo& Process::info() const noexcept {
    TESSERA_ASSERT(state_ != nullptr);
    return state_->info;
}

DiagnosticObserver* Process::observer() const noexcept {
    TESSERA_ASSERT(state_ != nullptr);
    return state_->observer;
}

Result<bool> Process::is_alive() const noexcept {
    TESSERA_ASSERT(state_ != nullptr);
    if (state_->backend.load(std::memory_order_acquire) != nullptr && state_->handle == nullptr) {
        return true;
    }
    if (state_->info.is_local && state_->handle == ::GetCurrentProcess()) {
        return true;
    }
    DWORD exit_code = 0;
    if (!::GetExitCodeProcess(static_cast<HANDLE>(state_->handle), &exit_code)) {
        return fail(ErrorCode::AccessDenied, "GetExitCodeProcess", ::GetLastError());
    }
    return exit_code == STILL_ACTIVE;
}

namespace platform::windows {

Result<Process> from_native_handle(NativeHandle handle, Ownership ownership, ProcessAccess granted_access,
                                   DiagnosticObserver* observer) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::InvalidArgument, "from_native_handle", 0, "Invalid native handle");
    }

    const HANDLE win_handle = static_cast<HANDLE>(handle);
    auto close_on_fail = [&]() noexcept {
        if (ownership == Ownership::Owned && win_handle != ::GetCurrentProcess()) {
            ::CloseHandle(win_handle);
        }
    };

    const DWORD pid =
        (win_handle == ::GetCurrentProcess()) ? ::GetCurrentProcessId() : ::GetProcessId(win_handle);
    if (pid == 0) {
        const DWORD err = ::GetLastError();
        close_on_fail();
        return fail(ErrorCode::InvalidArgument, "GetProcessId", err, "Failed to query PID from handle");
    }

    auto arch_res = detect_target_architecture(win_handle);
    if (!arch_res) {
        close_on_fail();
        diagnostics::notify(observer, DiagnosticSeverity::Error, "Process",
                            "Target architecture unsupported or query failed", arch_res.error());
        return std::unexpected(arch_res.error());
    }

    DWORD exit_code = 0;
    if (win_handle != ::GetCurrentProcess() && ::GetExitCodeProcess(win_handle, &exit_code)) {
        if (exit_code != STILL_ACTIVE) {
            close_on_fail();
            return fail(ErrorCode::ProcessExited, "GetExitCodeProcess", 0,
                        "Target process has already exited");
        }
    }

    try {
        auto st = std::make_shared<detail::ProcessState>();
        st->handle = win_handle;
        st->ownership = ownership;
        st->observer = observer;
        const Architecture arch = *arch_res;
        st->info = ProcessInfo{
            .pid = ProcessId{pid},
            .architecture = arch,
            .pointer_size = (arch == Architecture::X64) ? std::uint8_t{8} : std::uint8_t{4},
            .is_local = (pid == ::GetCurrentProcessId()),
            .granted_access = granted_access,
            .max_application_address = query_native_max_app_address(arch),
        };
        return Process{std::move(st)};
    } catch (const std::bad_alloc&) {
        close_on_fail();
        return fail(ErrorCode::OutOfMemory, "from_native_handle");
    }
}

NativeHandle native_handle(const Process& process) noexcept {
    return process.state() ? process.state()->handle : nullptr;
}

} // namespace platform::windows

} // namespace tessera
