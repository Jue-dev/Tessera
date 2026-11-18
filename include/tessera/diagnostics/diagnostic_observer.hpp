#pragma once

#include <cstdint>
#include <optional>
#include <source_location>
#include <string_view>

#include "tessera/core/error.hpp"

namespace tessera::diagnostics {

enum class DiagnosticSeverity : std::uint8_t {
    Info,
    Warning,
    Error,
};

struct DiagnosticEvent {
    DiagnosticSeverity severity = DiagnosticSeverity::Info;
    std::string_view category{};
    std::string_view message{};
    std::optional<tessera::Error> error{};
    std::source_location location = std::source_location::current();
};

class DiagnosticObserver {
public:
    virtual ~DiagnosticObserver() = default;
    virtual void on_diagnostic(const DiagnosticEvent& event) noexcept = 0;
};

class NullDiagnosticObserver final : public DiagnosticObserver {
public:
    void on_diagnostic(const DiagnosticEvent&) noexcept override {}
};

inline void notify(DiagnosticObserver* observer,
                   DiagnosticSeverity severity,
                   std::string_view category,
                   std::string_view message,
                   std::optional<tessera::Error> err = std::nullopt,
                   std::source_location loc = std::source_location::current()) noexcept {
    if (observer != nullptr) {
        DiagnosticEvent ev{
            .severity = severity,
            .category = category,
            .message = message,
            .error = std::move(err),
            .location = loc,
        };
        observer->on_diagnostic(ev);
    }
}

} // namespace tessera::diagnostics

namespace tessera {
using diagnostics::DiagnosticEvent;
using diagnostics::DiagnosticObserver;
using diagnostics::DiagnosticSeverity;
} // namespace tessera
