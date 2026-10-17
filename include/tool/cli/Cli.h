#pragma once

#include <iosfwd>

namespace tool::core {
class Logger;
}

namespace tool::cli {

// Exit status 3 means the command is recognized but belongs to a later phase.
inline constexpr int kCommandUnavailable = 3;

int run_cli(int argc, const char* const argv[], std::ostream& output,
            std::ostream& errors, core::Logger& logger);

}  // namespace tool::cli
