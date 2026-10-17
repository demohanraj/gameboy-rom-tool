#pragma once

#include <iosfwd>
#include <string_view>

namespace tool::core {

enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
};

[[nodiscard]] std::string_view to_string(LogLevel level) noexcept;

class Logger {
public:
    explicit Logger(LogLevel minimum_level = LogLevel::Info);
    Logger(std::ostream& output, std::ostream& errors, LogLevel minimum_level = LogLevel::Info);

    void set_minimum_level(LogLevel minimum_level) noexcept;
    [[nodiscard]] LogLevel minimum_level() const noexcept;
    void log(LogLevel level, std::string_view message) const;

private:
    std::ostream* output_;
    std::ostream* errors_;
    LogLevel minimum_level_;
};

}  // namespace tool::core
