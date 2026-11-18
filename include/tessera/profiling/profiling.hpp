#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <string_view>

#include "tessera/core/function_ref.hpp"

namespace tessera::profiling {

class Stopwatch {
public:
    using Clock = std::chrono::steady_clock;

    Stopwatch() noexcept : start_(Clock::now()) {}

    void restart() noexcept { start_ = Clock::now(); }

    [[nodiscard]] std::chrono::nanoseconds elapsed() const noexcept {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start_);
    }

    [[nodiscard]] double elapsed_ms() const noexcept {
        return std::chrono::duration<double, std::milli>(Clock::now() - start_).count();
    }

    [[nodiscard]] double elapsed_us() const noexcept {
        return std::chrono::duration<double, std::micro>(Clock::now() - start_).count();
    }

private:
    Clock::time_point start_;
};

// RAII scope timer that reports elapsed duration via callback without depending on logging.
class ScopeTimer {
public:
    using Callback = std::move_only_function<void(std::string_view, std::chrono::nanoseconds)>;

    ScopeTimer(std::string_view label, Callback on_complete) noexcept
        : label_(label), callback_(std::move(on_complete)) {}

    ScopeTimer(const ScopeTimer&) = delete;
    ScopeTimer& operator=(const ScopeTimer&) = delete;

    ~ScopeTimer() noexcept {
        if (callback_) {
            try {
                callback_(label_, stopwatch_.elapsed());
            } catch (...) {
            }
        }
    }

    void cancel() noexcept { callback_ = nullptr; }

    [[nodiscard]] std::chrono::nanoseconds elapsed() const noexcept {
        return stopwatch_.elapsed();
    }

private:
    std::string_view label_{};
    Stopwatch stopwatch_{};
    Callback callback_{};
};

struct BenchmarkMetrics {
    std::size_t iterations = 0;
    std::chrono::nanoseconds total{};
    std::chrono::nanoseconds min{};
    std::chrono::nanoseconds max{};
    std::chrono::nanoseconds mean{};
};

[[nodiscard]] BenchmarkMetrics run_benchmark(std::size_t iterations,
                                             FunctionRef<void()> body);

} // namespace tessera::profiling
