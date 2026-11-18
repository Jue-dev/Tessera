#include "tessera/logging/logging.hpp"

#include <Windows.h>

#include <ctime>
#include <new>

#include "tessera/diagnostics/error_format.hpp"
#include "tessera/utility/encoding.hpp"

namespace tessera::logging {

std::string format_log_record(const LogRecord& record) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        record.timestamp.time_since_epoch()) %
                    1000;
    const std::time_t tt = std::chrono::system_clock::to_time_t(record.timestamp);
    std::tm local_tm{};
    localtime_s(&local_tm, &tt);

    return std::format("[{:02d}:{:02d}:{:02d}.{:03d}] [{}] [{}] {}",
                       local_tm.tm_hour,
                       local_tm.tm_min,
                       local_tm.tm_sec,
                       static_cast<int>(ms.count()),
                       level_name(record.level),
                       record.category,
                       record.message);
}

ConsoleSink::ConsoleSink(bool enable_ansi_color) noexcept {
    if (!enable_ansi_color) {
        return;
    }
    const HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD mode = 0;
    if (!::GetConsoleMode(h, &mode)) {
        return;
    }
    if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 ||
        ::SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        use_color_ = true;
    }
}

void ConsoleSink::write(const LogRecord& record) noexcept {
    if (!enabled()) {
        return;
    }
    const HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        return;
    }
    try {
        std::string line = format_log_record(record);
        if (use_color_) {
            std::string_view color = "\x1b[0m";
            switch (record.level) {
                case LogLevel::Trace:    color = "\x1b[90m"; break;
                case LogLevel::Debug:    color = "\x1b[36m"; break;
                case LogLevel::Info:     color = "\x1b[32m"; break;
                case LogLevel::Warn:     color = "\x1b[33m"; break;
                case LogLevel::Error:    color = "\x1b[31m"; break;
                case LogLevel::Critical: color = "\x1b[1;31m"; break;
                case LogLevel::Off:      break;
            }
            line = std::format("{}{}\x1b[0m\n", color, line);
        } else {
            line.push_back('\n');
        }

        const std::lock_guard<std::mutex> lock(mutex_);
        DWORD written = 0;
        ::WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    } catch (...) {
    }
}

void DebuggerSink::write(const LogRecord& record) noexcept {
    if (!enabled()) {
        return;
    }
    try {
        std::string line = format_log_record(record);
        line.push_back('\n');
        if (auto u16 = encoding::utf8_to_utf16(line)) {
            ::OutputDebugStringW(reinterpret_cast<LPCWSTR>(u16->c_str()));
        }
    } catch (...) {
    }
}

Result<std::shared_ptr<FileSink>> FileSink::create(const std::filesystem::path& file_path,
                                                   bool append) {
    if (file_path.empty()) {
        return fail(ErrorCode::InvalidArgument, "FileSink::create");
    }
    const auto parent = file_path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }

    const DWORD disposition = append ? OPEN_ALWAYS : CREATE_ALWAYS;
    const HANDLE h = ::CreateFileW(file_path.c_str(),
                                   FILE_APPEND_DATA | GENERIC_WRITE,
                                   FILE_SHARE_READ,
                                   nullptr,
                                   disposition,
                                   FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return fail(ErrorCode::IoError, "CreateFileW(FileSink)", ::GetLastError());
    }
    if (append) {
        ::SetFilePointerEx(h, LARGE_INTEGER{}, nullptr, FILE_END);
    }

    try {
        return std::shared_ptr<FileSink>(new FileSink(h));
    } catch (const std::bad_alloc&) {
        ::CloseHandle(h);
        return fail(ErrorCode::OutOfMemory, "FileSink::create");
    }
}

FileSink::~FileSink() noexcept {
    if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
}

void FileSink::write(const LogRecord& record) noexcept {
    if (!enabled() || handle_ == nullptr) {
        return;
    }
    try {
        std::string line = format_log_record(record);
        line.push_back('\n');
        const std::lock_guard<std::mutex> lock(mutex_);
        DWORD written = 0;
        ::WriteFile(static_cast<HANDLE>(handle_),
                    line.data(),
                    static_cast<DWORD>(line.size()),
                    &written,
                    nullptr);
    } catch (...) {
    }
}

void FileSink::flush() noexcept {
    if (handle_ != nullptr) {
        const std::lock_guard<std::mutex> lock(mutex_);
        ::FlushFileBuffers(static_cast<HANDLE>(handle_));
    }
}

void MemorySink::write(const LogRecord& record) noexcept {
    if (!enabled()) {
        return;
    }
    try {
        const std::lock_guard<std::mutex> lock(mutex_);
        records_.push_back(record);
    } catch (...) {
    }
}

std::vector<LogRecord> MemorySink::records() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return records_;
}

void MemorySink::clear() noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);
    records_.clear();
}

void Logger::add_sink(std::shared_ptr<LogSink> sink) {
    if (!sink) {
        return;
    }
    const std::lock_guard<std::mutex> lock(sinks_mutex_);
    sinks_.push_back(std::move(sink));
}

void Logger::clear_sinks() noexcept {
    const std::lock_guard<std::mutex> lock(sinks_mutex_);
    sinks_.clear();
}

void Logger::log_raw(LogLevel level,
                     std::string message,
                     std::source_location loc) const noexcept {
    if (!should_log(level)) {
        return;
    }
    try {
        const LogRecord rec{
            .timestamp = std::chrono::system_clock::now(),
            .level = level,
            .category = category_,
            .thread_id = ::GetCurrentThreadId(),
            .location = loc,
            .message = std::move(message),
        };
        std::vector<std::shared_ptr<LogSink>> snapshot;
        {
            const std::lock_guard<std::mutex> lock(sinks_mutex_);
            snapshot = sinks_;
        }
        for (const auto& s : snapshot) {
            if (s && s->enabled()) {
                s->write(rec);
            }
        }
    } catch (...) {
    }
}

void LoggerDiagnosticObserver::on_diagnostic(const DiagnosticEvent& event) noexcept {
    if (!logger_) {
        return;
    }
    LogLevel lvl = LogLevel::Info;
    switch (event.severity) {
        case DiagnosticSeverity::Info:    lvl = LogLevel::Info; break;
        case DiagnosticSeverity::Warning: lvl = LogLevel::Warn; break;
        case DiagnosticSeverity::Error:   lvl = LogLevel::Error; break;
    }
    if (!logger_->should_log(lvl)) {
        return;
    }
    try {
        std::string msg(event.message);
        if (event.error.has_value()) {
            msg += std::format(" ({})", diagnostics::describe(*event.error));
        }
        logger_->log_raw(lvl, std::move(msg), event.location);
    } catch (...) {
    }
}

} // namespace tessera::logging
