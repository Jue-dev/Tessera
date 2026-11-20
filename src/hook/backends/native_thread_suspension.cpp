#include "native_thread_suspension.hpp"

#include <exception>
#include <new>
#include <utility>

#include "address_range.hpp"

namespace tessera::detail::native_hook {

SuspendedThreads::SuspendedThreads(SuspendedThreads&& other) noexcept
    : thread_list_(std::move(other.thread_list_)),
      suspended_(std::move(other.suspended_)),
      policy_(other.policy_) {}

SuspendedThreads::~SuspendedThreads() noexcept {
    resume_all();
}

Result<SuspendedThreads> SuspendedThreads::acquire(ThreadPolicy policy) {
    SuspendedThreads result{};
    result.policy_ = policy;
    if (policy == ThreadPolicy::None) {
        return result;
    }

    auto list = platform::windows::ScopedThreadList::collect_other_threads(policy);
    if (!list) {
        return std::unexpected(list.error());
    }
    result.thread_list_ = std::move(*list);

    try {
        result.suspended_.reserve(result.thread_list_.handles().size());
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::OutOfMemory, "SuspendedThreads::acquire");
    }

    for (void* raw_handle : result.thread_list_.handles()) {
        const HANDLE thread = static_cast<HANDLE>(raw_handle);
        if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
            const DWORD error = ::GetLastError();
            if (policy == ThreadPolicy::SuspendOthersStrict) {
                return fail(ErrorCode::ThreadEnumerationFailed,
                            "SuspendThread", error, "Strict thread suspension failed");
            }
            continue;
        }
        result.suspended_.push_back(thread);
    }
    return result;
}

void SuspendedThreads::resume() noexcept {
    resume_all();
}

Status SuspendedThreads::ensure_outside(std::uintptr_t begin,
                                        std::size_t size,
                                        std::uintptr_t second_begin,
                                        std::size_t second_size) const noexcept {
    if (policy_ == ThreadPolicy::None) {
        return ok();
    }
    for (HANDLE thread : suspended_) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!::GetThreadContext(thread, &context)) {
            const DWORD error = ::GetLastError();
            if (policy_ == ThreadPolicy::SuspendOthersStrict) {
                return fail(ErrorCode::ThreadEnumerationFailed,
                            "GetThreadContext", error, "Thread context query failed");
            }
            continue;
        }
#if defined(_M_X64) || defined(__x86_64__)
        const std::uintptr_t instruction_pointer = static_cast<std::uintptr_t>(context.Rip);
#else
        const std::uintptr_t instruction_pointer = static_cast<std::uintptr_t>(context.Eip);
#endif
        if (address_range_contains(begin, size, instruction_pointer) ||
            address_range_contains(second_begin, second_size, instruction_pointer)) {
            return fail(ErrorCode::Conflict,
                        "NativeInlineHook::thread_ip", 0, "Thread is inside the patch range");
        }
    }
    return ok();
}

void SuspendedThreads::resume_all() noexcept {
    for (auto it = suspended_.rbegin(); it != suspended_.rend(); ++it) {
        const HANDLE thread = *it;
        if (::ResumeThread(thread) == static_cast<DWORD>(-1)) {
            if (::WaitForSingleObject(thread, 0) != WAIT_OBJECT_0) {
                std::terminate();
            }
        }
    }
    suspended_.clear();
}

} // namespace tessera::detail::native_hook
