#include "tessera/json/json.hpp"
#include "tessera/profiling/profiling.hpp"

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>

int main() {
    std::string payload = R"({"schema":1,"records":[)";
    constexpr std::size_t record_count = 512;
    for (std::size_t i = 0; i < record_count; ++i) {
        if (i != 0) {
            payload.push_back(',');
        }
        payload += R"({"id":)";
        payload += std::to_string(i);
        payload += R"(,"name":"profile-record-)";
        payload += std::to_string(i);
        payload += R"(","enabled":true,"values":[1,2,3,5,8,13],"metadata":{"source":"benchmark","revision":7}})";
    }
    payload += "]}";

    const auto parsed = tessera::json::parse(payload);
    if (!parsed) {
        std::cerr << "JSON benchmark fixture failed to parse\n";
        return 1;
    }

    const auto parse_metrics = tessera::profiling::run_benchmark(40, [&] {
        const auto result = tessera::json::parse(payload);
        if (!result) {
            std::abort();
        }
    });
    const auto write_metrics = tessera::profiling::run_benchmark(40, [&] {
        const auto result = tessera::json::write(*parsed);
        if (!result || result->empty()) {
            std::abort();
        }
    });

    std::cout << "json parse records=" << record_count
              << " iterations=" << parse_metrics.iterations
              << " mean_ns=" << parse_metrics.mean.count() << '\n';
    std::cout << "json write records=" << record_count
              << " iterations=" << write_metrics.iterations
              << " mean_ns=" << write_metrics.mean.count() << '\n';
    return 0;
}
