#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <atomic>
#include <thread>
#include <vector>

#include "tessera/diagnostics/diagnostics.hpp"
#include "tessera/logging/logging.hpp"
#include "tessera/profiling/profiling.hpp"

namespace {

class RecordingObserver final : public tessera::diagnostics::DiagnosticObserver {
public:
    void on_diagnostic(const tessera::diagnostics::DiagnosticEvent& event) noexcept override {
        events_.push_back(event);
    }

    std::vector<tessera::diagnostics::DiagnosticEvent> events_{};
};

} // namespace

TEST_CASE("Logger levels and sink filtering are deterministic", "[logging]") {
    using namespace tessera::logging;

    REQUIRE(level_name(LogLevel::Trace) == "TRACE");
    REQUIRE(level_name(LogLevel::Debug) == "DEBUG");
    REQUIRE(level_name(LogLevel::Info) == "INFO ");
    REQUIRE(level_name(LogLevel::Warn) == "WARN ");
    REQUIRE(level_name(LogLevel::Error) == "ERROR");
    REQUIRE(level_name(LogLevel::Critical) == "CRIT ");
    REQUIRE(level_name(LogLevel::Off) == "OFF  ");

    auto memory = std::make_shared<MemorySink>();
    auto filtered = std::make_shared<MemorySink>();
    filtered->set_enabled(false);
    Logger logger{"infra", LogLevel::Trace};
    logger.add_sink(memory);
    logger.add_sink(filtered);

    logger.trace("trace");
    logger.debug("debug");
    logger.info("info");
    logger.warn("warn");
    logger.error("error");
    logger.critical("critical");
    logger.log(LogLevel::Off, "off");
    REQUIRE(memory->records().size() == 6);
    REQUIRE(filtered->records().empty());

    const auto records = memory->records();
    REQUIRE(records.front().level == LogLevel::Trace);
    REQUIRE(records.front().category == "infra");
    REQUIRE(records.front().message == "trace");
    REQUIRE(records.back().level == LogLevel::Critical);
    const std::string formatted = format_log_record(records.front());
    REQUIRE(formatted.find("TRACE") != std::string::npos);
    REQUIRE(formatted.find("[infra] trace") != std::string::npos);

    logger.set_min_level(LogLevel::Warn);
    logger.info("below threshold");
    logger.warn("at threshold");
    REQUIRE(memory->records().size() == 7);
    REQUIRE(memory->records().back().message == "at threshold");
    REQUIRE(logger.min_level() == LogLevel::Warn);

    memory->clear();
    REQUIRE(memory->records().empty());
    logger.clear_sinks();
    logger.error("no sink attached");
    REQUIRE(memory->records().empty());
}

TEST_CASE("Logger supports concurrent writes and sink registry updates", "[logging][concurrency]") {
    using namespace tessera::logging;

    auto sink = std::make_shared<MemorySink>();
    Logger logger{"concurrent", LogLevel::Trace};
    logger.add_sink(sink);
    std::atomic<int> writes{0};

    std::array<std::jthread, 4> writers;
    for (std::size_t worker = 0; worker < writers.size(); ++worker) {
        writers[worker] = std::jthread([&, worker] {
            for (int i = 0; i < 100; ++i) {
                logger.info("worker={} sequence={}", worker, i);
                writes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    std::jthread updater([&] {
        for (int i = 0; i < 100; ++i) {
            logger.set_min_level((i % 2) == 0 ? LogLevel::Trace : LogLevel::Info);
            sink->set_enabled((i % 3) != 0);
            logger.clear_sinks();
            logger.add_sink(sink);
        }
    });

    for (auto& writer : writers) {
        writer.join();
    }
    updater.join();
    logger.set_min_level(LogLevel::Trace);
    sink->set_enabled(true);
    logger.add_sink(sink);
    logger.info("final-record");

    REQUIRE(writes.load(std::memory_order_relaxed) == 400);
    const auto records = sink->records();
    REQUIRE_FALSE(records.empty());
    REQUIRE(records.back().message == "final-record");
}

TEST_CASE("Diagnostics format errors and notify observers", "[diagnostics]") {
    using namespace tessera;

    REQUIRE(diagnostics::format_native_error(0).empty());
    REQUIRE(diagnostics::format_address(Address{0x1234}, 4) == "0x00001234");
    REQUIRE(diagnostics::format_address(Address{0x1234}) == "0x0000000000001234");

    const Error error{
        .code = ErrorCode::NotFound,
        .native = 0,
        .operation = "TypeRegistry::find",
        .detail = "type is not registered",
    };
    REQUIRE(diagnostics::describe(error) ==
            "NotFound in TypeRegistry::find: type is not registered");

    RecordingObserver observer;
    diagnostics::notify(&observer, DiagnosticSeverity::Info, "test", "started");
    diagnostics::notify(&observer, DiagnosticSeverity::Warning, "test", "missing optional field", error);
    diagnostics::notify(&observer, DiagnosticSeverity::Error, "test", "lookup failed");
    diagnostics::notify(nullptr, DiagnosticSeverity::Info, "test", "ignored");
    REQUIRE(observer.events_.size() == 3);
    REQUIRE(observer.events_[0].severity == DiagnosticSeverity::Info);
    REQUIRE(observer.events_[1].category == "test");
    REQUIRE(observer.events_[1].message == "missing optional field");
    REQUIRE(observer.events_[1].error.has_value());
    REQUIRE(observer.events_[2].severity == DiagnosticSeverity::Error);
}

TEST_CASE("LoggerDiagnosticObserver maps diagnostic severity and formats attached errors",
          "[logging][diagnostics]") {
    using namespace tessera;

    auto sink = std::make_shared<logging::MemorySink>();
    auto logger = std::make_shared<logging::Logger>("observer", logging::LogLevel::Trace);
    logger->add_sink(sink);
    logging::LoggerDiagnosticObserver observer{logger};

    diagnostics::notify(&observer, DiagnosticSeverity::Info, "unit", "information");
    diagnostics::notify(&observer, DiagnosticSeverity::Warning, "unit", "warning");
    diagnostics::notify(&observer,
                        DiagnosticSeverity::Error,
                        "unit",
                        "failure",
                        Error{.code = ErrorCode::IoError, .operation = "read", .detail = "disk"});
    REQUIRE(sink->records().size() == 3);
    REQUIRE(sink->records()[0].level == logging::LogLevel::Info);
    REQUIRE(sink->records()[1].level == logging::LogLevel::Warn);
    REQUIRE(sink->records()[2].level == logging::LogLevel::Error);
    REQUIRE(sink->records()[2].message == "failure (IoError in read: disk)");

    logger->set_min_level(logging::LogLevel::Critical);
    diagnostics::notify(&observer, DiagnosticSeverity::Error, "unit", "filtered");
    REQUIRE(sink->records().size() == 3);
}

TEST_CASE("Profiling ScopeTimer reports elapsed duration", "[profiling]") {
    using namespace tessera;

    std::chrono::nanoseconds elapsed{-1};
    bool correct_name = false;
    {
        profiling::ScopeTimer timer(
            "infra-test", [&](std::string_view name, std::chrono::nanoseconds duration) {
                correct_name = name == "infra-test";
                elapsed = duration;
            });
    }
    REQUIRE(correct_name);
    REQUIRE(elapsed.count() >= 0);
}
