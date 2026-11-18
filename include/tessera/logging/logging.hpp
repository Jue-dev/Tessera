#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <memory>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>
#include <vector>

#include "tessera/core/result.hpp"
#include "tessera/diagnostics/diagnostic_observer.hpp"

namespace tessera::logging {

enum class LogLevel : std::uint8_t {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
    Off = 6,
};

[[nodiscard]] constexpr std::string_view level_name(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Trace:    return "TRACE";
        case LogLevel::Debug:    return "DEBUG";
        case LogLevel::Info:     return "INFO ";
        case LogLevel::Warn:     return "WARN ";
        case LogLevel::Error:    return "ERROR";
        case LogLevel::Critical: return "CRIT ";
        case LogLevel::Off:      return "OFF  ";
    }
    return "INFO ";
}

struct LogRecord {
    std::chrono::system_clock::time_point timestamp{};
    LogLevel level = LogLevel::Info;
    std::string_view category{};
    std::uint32_t thread_id = 0;
    std::source_location location = std::source_location::current();
    std::string message{};
};

[[nodiscard]] std::string format_log_record(const LogRecord& record);

class LogSink {
public:
    virtual ~LogSink() = default;

    virtual void write(const LogRecord& record) noexcept = 0;
    virtual void flush() noexcept {}

    void set_enabled(bool enabled) noexcept {
        enabled_.store(enabled, std::memory_order_relaxed);
    }

    [[nodiscard]] bool enabled() const noexcept {
        return enabled_.load(std::memory_order_relaxed);
    }

private:
    std::atomic<bool> enabled_{true};
};

// Writes to the process's existing stdout/stderr console handle without allocating a new console.
class ConsoleSink final : public LogSink {
public:
    explicit ConsoleSink(bool enable_ansi_color = true) noexcept;
    void write(const LogRecord& record) noexcept override;

private:
    std::mutex mutex_{};
    bool use_color_ = false;
};

// Writes formatted lines via OutputDebugStringW.
class DebuggerSink final : public LogSink {
public:
    void write(const LogRecord& record) noexcept override;
};

// Thread-safe file sink.
class FileSink final : public LogSink {
public:
    [[nodiscard]] static Result<std::shared_ptr<FileSink>> create(
        const std::filesystem::path& file_path,
        bool append = true);

    ~FileSink() noexcept override;

    void write(const LogRecord& record) noexcept override;
    void flush() noexcept override;

private:
    explicit FileSink(void* file_handle) noexcept : handle_(file_handle) {}

    std::mutex mutex_{};
    void* handle_ = nullptr;
};

// In-memory sink useful for tests and inspection.
class MemorySink final : public LogSink {
public:
    void write(const LogRecord& record) noexcept override;
    [[nodiscard]] std::vector<LogRecord> records() const;
    void clear() noexcept;

private:
    mutable std::mutex mutex_{};
    std::vector<LogRecord> records_{};
};

// Thread-safe synchronous logger. If a message's level is below min_level(), std::format is never called.
class Logger {
public:
    explicit Logger(std::string category, LogLevel min_level = LogLevel::Info)
        : category_(std::move(category)), min_level_(min_level) {}

    void set_min_level(LogLevel level) noexcept {
        min_level_.store(level, std::memory_order_relaxed);
    }

    [[nodiscard]] LogLevel min_level() const noexcept {
        return min_level_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::string_view category() const noexcept { return category_; }

    void add_sink(std::shared_ptr<LogSink> sink);
    void clear_sinks() noexcept;

    [[nodiscard]] bool should_log(LogLevel level) const noexcept {
        return level != LogLevel::Off &&
               static_cast<std::uint8_t>(level) >=
                   static_cast<std::uint8_t>(min_level_.load(std::memory_order_relaxed));
    }

    void log_raw(LogLevel level,
                 std::string message,
                 std::source_location loc = std::source_location::current()) const noexcept;

    template <class... Args>
    void log(LogLevel level,
             std::format_string<Args...> fmt,
             Args&&... args) const noexcept {
        if (!should_log(level)) {
            return;
        }
        try {
            log_raw(level, std::format(fmt, std::forward<Args>(args)...));
        } catch (...) {
        }
    }

    template <class... Args>
    void trace(std::format_string<Args...> fmt, Args&&... args) const noexcept {
        log(LogLevel::Trace, fmt, std::forward<Args>(args)...);
    }

    template <class... Args>
    void debug(std::format_string<Args...> fmt, Args&&... args) const noexcept {
        log(LogLevel::Debug, fmt, std::forward<Args>(args)...);
    }

    template <class... Args>
    void info(std::format_string<Args...> fmt, Args&&... args) const noexcept {
        log(LogLevel::Info, fmt, std::forward<Args>(args)...);
    }

    template <class... Args>
    void warn(std::format_string<Args...> fmt, Args&&... args) const noexcept {
        log(LogLevel::Warn, fmt, std::forward<Args>(args)...);
    }

    template <class... Args>
    void error(std::format_string<Args...> fmt, Args&&... args) const noexcept {
        log(LogLevel::Error, fmt, std::forward<Args>(args)...);
    }

    template <class... Args>
    void critical(std::format_string<Args...> fmt, Args&&... args) const noexcept {
        log(LogLevel::Critical, fmt, std::forward<Args>(args)...);
    }

private:
    std::string category_;
    std::atomic<LogLevel> min_level_{LogLevel::Info};
    mutable std::mutex sinks_mutex_{};
    std::vector<std::shared_ptr<LogSink>> sinks_{};
};

// Adapter forwarding DiagnosticObserver notifications to a Logger instance.
class LoggerDiagnosticObserver final : public DiagnosticObserver {
public:
    explicit LoggerDiagnosticObserver(std::shared_ptr<Logger> logger) noexcept
        : logger_(std::move(logger)) {}

    void on_diagnostic(const DiagnosticEvent& event) noexcept override;

private:
    std::shared_ptr<Logger> logger_;
};

} // namespace tessera::logging
