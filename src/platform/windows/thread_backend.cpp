#include "platform/windows/thread_backend.hpp"

#include <Windows.h>
#include <TlHelp32.h>

#include <cstdio>
#include <exception>
#include <new>
#include <utility>

namespace tessera::platform::windows {

namespace {
void close_owned_handle(HANDLE handle) noexcept {
    if (handle != nullptr && !::CloseHandle(handle)) {
        const DWORD error = ::GetLastError();
        std::fprintf(stderr,
                     "Tessera: CloseHandle failed for an owned thread-enumeration handle (error=%lu)\n",
                     static_cast<unsigned long>(error));
        // Dropping an owned snapshot/thread handle after a failed close silently
        // leaks process resources. The cleanup invariant is therefore fail-stop.
        std::terminate();
    }
}
} // namespace

ScopedThreadList::ScopedThreadList(ScopedThreadList&& other) noexcept
    : handles_(std::move(other.handles_)) {}

ScopedThreadList& ScopedThreadList::operator=(ScopedThreadList&& other) noexcept {
    if (this != &other) {
        close_all();
        handles_ = std::move(other.handles_);
    }
    return *this;
}

ScopedThreadList::~ScopedThreadList() noexcept {
    close_all();
}

void ScopedThreadList::close_all() noexcept {
    for (void* h : handles_) {
        if (h != nullptr) {
            close_owned_handle(static_cast<HANDLE>(h));
        }
    }
    handles_.clear();
}

Result<ScopedThreadList> ScopedThreadList::collect_other_threads(
    ThreadPolicy policy, bool require_context_write) {
    if (policy == ThreadPolicy::None) {
        return ScopedThreadList{};
    }

    const HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        if (policy == ThreadPolicy::SuspendOthersStrict) {
            return fail(ErrorCode::ThreadEnumerationFailed,
                        "CreateToolhelp32Snapshot",
                        err,
                        "Failed to create thread snapshot");
        }
        return ScopedThreadList{};
    }

    ScopedThreadList list{};
    const DWORD pid = ::GetCurrentProcessId();
    const DWORD current_tid = ::GetCurrentThreadId();

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (!::Thread32First(snap, &te)) {
        const DWORD err = ::GetLastError();
        close_owned_handle(snap);
        if (policy == ThreadPolicy::SuspendOthersStrict) {
            return fail(ErrorCode::ThreadEnumerationFailed, "Thread32First", err);
        }
        return list;
    }

    try {
        for (;;) {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD) &&
                te.th32OwnerProcessID == pid && te.th32ThreadID != current_tid) {
                // The native inline backend needs suspend, context-read, and
                // wait rights. Detours additionally needs context-write rights
                // because its transaction commit may repair an enlisted IP.
                DWORD desired = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | SYNCHRONIZE;
                if (require_context_write) {
                    desired |= THREAD_SET_CONTEXT;
                }
                const HANDLE th = ::OpenThread(desired, FALSE, te.th32ThreadID);
                if (th != nullptr) {
                    try {
                        list.handles_.push_back(th);
                    } catch (...) {
                        // Ownership transfers to the list only after push_back
                        // succeeds; close the just-opened handle on allocation failure.
                        close_owned_handle(th);
                        throw;
                    }
                } else {
                    const DWORD err = ::GetLastError();
                    // ERROR_INVALID_PARAMETER indicates the thread already exited between snapshot and OpenThread.
                    if (err != ERROR_INVALID_PARAMETER && policy == ThreadPolicy::SuspendOthersStrict) {
                        close_owned_handle(snap);
                        return fail(ErrorCode::ThreadEnumerationFailed,
                                    "OpenThread",
                                    err,
                                    "Strict thread policy aborted hook transaction due to OpenThread failure");
                    }
                }
            }
            te.dwSize = sizeof(te);
            // GetLastError is undefined after a successful Win32 call. Reset
            // it before Thread32Next so a stale error from an earlier API
            // cannot be mistaken for an enumeration failure at end-of-list.
            ::SetLastError(ERROR_SUCCESS);
            if (!::Thread32Next(snap, &te)) {
                break;
            }
        }
    } catch (const std::bad_alloc&) {
        close_owned_handle(snap);
        return fail(ErrorCode::OutOfMemory, "ScopedThreadList::collect_other_threads");
    } catch (...) {
        close_owned_handle(snap);
        throw;
    }

    const DWORD enumeration_error = ::GetLastError();
    if (enumeration_error != ERROR_NO_MORE_FILES && policy == ThreadPolicy::SuspendOthersStrict) {
        close_owned_handle(snap);
        return fail(ErrorCode::ThreadEnumerationFailed,
                    "Thread32Next",
                    enumeration_error,
                    "Strict thread policy aborted because thread enumeration ended unexpectedly");
    }

    close_owned_handle(snap);
    return list;
}

ProcessWideHookLock::ProcessWideHookLock() noexcept {
    wchar_t name_buf[96]{};
    std::swprintf(
        name_buf, std::size(name_buf), L"Local\\Tessera_HookTransactionMutex_%lu", ::GetCurrentProcessId());
    mutex_handle_ = ::CreateMutexW(nullptr, FALSE, name_buf);
    if (mutex_handle_ != nullptr) {
        const DWORD wait_res = ::WaitForSingleObject(static_cast<HANDLE>(mutex_handle_), INFINITE);
        if (wait_res == WAIT_ABANDONED) {
            // The previous owner may have terminated during a patch transaction.
            // Target bytes and the process-local ownership registry can no longer
            // be assumed consistent, so continuing to modify executable code is unsafe.
            std::terminate();
        }
        acquired_ = (wait_res == WAIT_OBJECT_0);
    }
}

ProcessWideHookLock::~ProcessWideHookLock() noexcept {
    if (mutex_handle_ != nullptr) {
        if (acquired_) {
            ::ReleaseMutex(static_cast<HANDLE>(mutex_handle_));
        }
        ::CloseHandle(static_cast<HANDLE>(mutex_handle_));
    }
}

} // namespace tessera::platform::windows
