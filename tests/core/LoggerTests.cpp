#include "tool/core/Logger.h"

#include <gtest/gtest.h>

#include <sstream>

namespace tool::core {

TEST(LoggerTests, WritesSeverityAndMessageToOutput) {
    std::ostringstream output;
    std::ostringstream errors;
    Logger logger(output, errors);

    logger.log(LogLevel::Info, "ROM loaded");

    EXPECT_EQ(output.str(), "[INFO] ROM loaded\n");
    EXPECT_TRUE(errors.str().empty());
}

TEST(LoggerTests, RoutesWarningsAndErrorsToErrorStream) {
    std::ostringstream output;
    std::ostringstream errors;
    Logger logger(output, errors);

    logger.log(LogLevel::Warning, "checksum mismatch");
    logger.log(LogLevel::Error, "invalid ROM");

    EXPECT_TRUE(output.str().empty());
    EXPECT_EQ(errors.str(), "[WARNING] checksum mismatch\n[ERROR] invalid ROM\n");
}

TEST(LoggerTests, FiltersMessagesBelowMinimumLevel) {
    std::ostringstream output;
    std::ostringstream errors;
    Logger logger(output, errors, LogLevel::Warning);

    logger.log(LogLevel::Info, "hidden");
    logger.log(LogLevel::Warning, "visible");

    EXPECT_TRUE(output.str().empty());
    EXPECT_EQ(errors.str(), "[WARNING] visible\n");
}

}  // namespace tool::core
