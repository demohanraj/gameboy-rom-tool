#include "tool/cli/Cli.h"
#include "tool/core/Logger.h"

#include <iostream>

int main(const int argc, const char* const argv[]) {
    tool::core::Logger logger;
    return tool::cli::run_cli(argc, argv, std::cout, std::cerr, logger);
}
