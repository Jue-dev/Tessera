#pragma once

#include <cstdint>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/hook/hook.hpp"

namespace tessera::platform::windows {

class ScopedThreadList {
public:
    ScopedThreadList() noexcept = default;
    ScopedThreadList(const ScopedThreadList&) = delete;
    ScopedThreadList& operator=(const ScopedThreadList&) = delete;
    ScopedThreadList(ScopedThreadList&& other) noexcept;
    ScopedThreadList& operator=(ScopedThreadList&& other) noexcept;
    ~ScopedThreadList() noexcept;

    // require_context_write is used by Microsoft Detours, which may repair
    // enlisted instruction pointers at transaction commit. The native backend
    // only inspects instruction pointers and keeps this disabled.
    [[nodiscard]] static Result<ScopedThreadList> collect_other_threads(
        ThreadPolicy policy,
        bool require_context_write = false);

    [[nodiscard]] const std::vector<void*>& handles() const noexcept { return handles_; }

private:
    void close_all() noexcept;
    std::vector<void*> handles_{};
};

// Acquires a process-wide named mutex so multiple static copies of Tessera within the same
// process serialize hook transactions safely.
class ProcessWideHookLock {
public:
    ProcessWideHookLock() noexcept;
    ProcessWideHookLock(const ProcessWideHookLock&) = delete;
    ProcessWideHookLock& operator=(const ProcessWideHookLock&) = delete;
    ~ProcessWideHookLock() noexcept;

    [[nodiscard]] bool acquired() const noexcept { return acquired_; }

private:
    void* mutex_handle_ = nullptr;
    bool acquired_ = false;
};

} // namespace tessera::platform::windows
