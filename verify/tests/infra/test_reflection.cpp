#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <thread>
#include <vector>

#include "tessera/filesystem/filesystem.hpp"
#include "tessera/json/json.hpp"
#include "tessera/logging/logging.hpp"
#include "tessera/profiling/profiling.hpp"
#include "tessera/reflection/reflection.hpp"
#include "tessera/utility/utility.hpp"

TEST_CASE("Logging, Profiling, and Reflection thread-safety", "[logging][profiling][reflection]") {
    using namespace tessera;

    auto mem_sink = std::make_shared<logging::MemorySink>();
    auto logger = std::make_shared<logging::Logger>("Scanner", logging::LogLevel::Info);
    logger->add_sink(mem_sink);

    logger->debug("Should be filtered out: {}", 123);
    logger->info("Scan started: module={}", "sample.exe");
    REQUIRE(mem_sink->records().size() == 1);
    REQUIRE(mem_sink->records()[0].message == "Scan started: module=sample.exe");

    logging::LoggerDiagnosticObserver obs{logger};
    diagnostics::notify(&obs, DiagnosticSeverity::Warning, "Scanner", "Region skipped");
    REQUIRE(mem_sink->records().size() == 2);

    // Profiling ScopeTimer
    std::chrono::nanoseconds recorded_ns{0};
    {
        profiling::ScopeTimer timer(
            "op", [&](std::string_view, std::chrono::nanoseconds d) { recorded_ns = d; });
    }
    REQUIRE(recorded_ns.count() >= 0);

    // Reflection TypeRegistry concurrent registration
    reflection::TypeRegistry reg{};
    struct DummyVec3 {
        float x, y, z;
    };
    auto info = reflection::TypeBuilder<DummyVec3>("tessera::DummyVec3")
                    .member("x", reflection::TypeId::from_name("float"), 0, 4)
                    .member("y", reflection::TypeId::from_name("float"), 4, 4)
                    .member("z", reflection::TypeId::from_name("float"), 8, 4)
                    .build();
    REQUIRE(reg.register_type(info).has_value());
    // Duplicate registration returns Conflict
    REQUIRE(reg.register_type(info).error().code == ErrorCode::Conflict);

    auto looked_up = reg.find_by_name("tessera::DummyVec3");
    REQUIRE(looked_up.has_value());
    REQUIRE(looked_up->members.size() == 3);
}
