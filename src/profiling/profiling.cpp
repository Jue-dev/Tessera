#include "tessera/profiling/profiling.hpp"

#include <algorithm>
#include <limits>

namespace tessera::profiling {

BenchmarkMetrics run_benchmark(std::size_t iterations, FunctionRef<void()> body) {
    if (iterations == 0 || !body) {
        return BenchmarkMetrics{};
    }

    BenchmarkMetrics metrics{};
    metrics.iterations = iterations;
    metrics.min = std::chrono::nanoseconds{(std::numeric_limits<long long>::max)()};
    metrics.max = std::chrono::nanoseconds{0};

    for (std::size_t i = 0; i < iterations; ++i) {
        Stopwatch sw{};
        body();
        const auto d = sw.elapsed();
        metrics.total += d;
        metrics.min = (std::min)(metrics.min, d);
        metrics.max = (std::max)(metrics.max, d);
    }

    metrics.mean = std::chrono::nanoseconds{
        metrics.total.count() / static_cast<long long>(iterations)};
    return metrics;
}

} // namespace tessera::profiling
