#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "platform/windows/thread_backend.hpp"
#include "tessera/hook/hook.hpp"

namespace tessera::detail::native_hook {

class SuspendedThreads {
public:
    SuspendedThreads() noexcept = default;
    SuspendedThreads(const SuspendedThreads&) = delete;
    SuspendedThreads& operator=(const SuspendedThreads&) = delete;
    SuspendedThreads(SuspendedThreads&& other) noexcept;
    SuspendedThreads& operator=(SuspendedThreads&&) = delete;

    ~SuspendedThreads() noexcept;

    [[nodiscard]] static Result<SuspendedThreads> acquire(ThreadPolicy policy);
    void resume() noexcept;
    [[nodiscard]] Status ensure_outside(std::uintptr_t begin,
                                        std::size_t size,
                                        std::uintptr_t second_begin = 0,
                                        std::size_t second_size = 0) const noexcept;

private:
    void resume_all() noexcept;

    platform::windows::ScopedThreadList thread_list_{};
    std::vector<HANDLE> suspended_{};
    ThreadPolicy policy_ = ThreadPolicy::SuspendOthersStrict;
};

} // namespace tessera::detail::native_hook
