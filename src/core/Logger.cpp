#include "tool/core/Logger.h"

#include <iostream>
#include <ostream>

namespace tool::core {

std::string_view to_string(const LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Trace:
            return "TRACE";
        case LogLevel::Debug:
            return "DEBUG";
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARNING";
        case LogLevel::Error:
            return "ERROR";
    }
    return "UNKNOWN";
}

Logger::Logger(const LogLevel minimum_level)
    : Logger(std::clog, std::cerr, minimum_level) {}

Logger::Logger(std::ostream& output, std::ostream& errors, const LogLevel minimum_level)
    : output_(&output), errors_(&errors), minimum_level_(minimum_level) {}

void Logger::set_minimum_level(const LogLevel minimum_level) noexcept {
    minimum_level_ = minimum_level;
}

LogLevel Logger::minimum_level() const noexcept {
    return minimum_level_;
}

void Logger::log(const LogLevel level, const std::string_view message) const {
    if (static_cast<int>(level) < static_cast<int>(minimum_level_)) {
        return;
    }

    std::ostream& destination = level >= LogLevel::Warning ? *errors_ : *output_;
    destination << '[' << to_string(level) << "] " << message << '\n';
}

}  // namespace tool::core
