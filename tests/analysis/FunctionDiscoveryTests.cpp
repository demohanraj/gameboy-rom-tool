#include "tool/analysis/FunctionDiscovery.h"
#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <stop_token>
#include <string>
#include <vector>

namespace tool::analysis {
namespace {

std::vector<std::uint8_t> make_function_fixture() {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0008U] = 0xC9U;
    bytes[0x0100U] = 0xC3U;  // JP $0150; remain in the reset function.
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $0160
    bytes[0x0151U] = 0x60U;
    bytes[0x0152U] = 0x01U;
    bytes[0x0153U] = 0xC4U;  // CALL NZ, $0170
    bytes[0x0154U] = 0x70U;
    bytes[0x0155U] = 0x01U;
    bytes[0x0156U] = 0xC9U;
    bytes[0x0160U] = 0xC9U;
    bytes[0x0170U] = 0xCFU;  // RST $08
    bytes[0x0171U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    return bytes;
}

const FunctionInfo* find_function(const FunctionDiscoveryResult& result,
                                  const std::uint16_t bank,
                                  const std::uint16_t address) {
    const auto found = std::find_if(result.functions.begin(), result.functions.end(),
        [bank, address](const FunctionInfo& function) {
            return function.bank == bank && function.cpu_address == address;
        });
    return found == result.functions.end() ? nullptr : &*found;
}

TEST(FunctionDiscoveryTests, FindsRootCallAndResetTargetsAndBuildsCallRelations) {
    test::TemporaryRomFile file(make_function_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto image = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(image.has_value()) << load_error.message;

    const FunctionDiscoveryResult result = discover_functions(*image);

    EXPECT_FALSE(result.cancelled);
    const FunctionInfo* reset = find_function(result, 0U, 0x0100U);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->name, "entry_0100");
    EXPECT_EQ(reset->start_evidence, FunctionStartEvidence::ResetEntry);
    EXPECT_NE(reset->callees.end(),
              std::find(reset->callees.begin(), reset->callees.end(), "fn_b0000_0160"));
    EXPECT_NE(reset->callees.end(),
              std::find(reset->callees.begin(), reset->callees.end(), "fn_b0000_0170"));

    const FunctionInfo* vblank = find_function(result, 0U, 0x0040U);
    ASSERT_NE(vblank, nullptr);
    EXPECT_EQ(vblank->name, "irq_vblank");
    EXPECT_EQ(vblank->start_evidence, FunctionStartEvidence::InterruptVector);

    const FunctionInfo* subroutine = find_function(result, 0U, 0x0160U);
    ASSERT_NE(subroutine, nullptr);
    EXPECT_EQ(subroutine->name, "sub_0160");
    EXPECT_EQ(subroutine->start_evidence, FunctionStartEvidence::DirectCall);
    EXPECT_EQ(subroutine->callers, (std::vector<std::string>{"fn_b0000_0100"}));

    const FunctionInfo* rst_target = find_function(result, 0U, 0x0008U);
    ASSERT_NE(rst_target, nullptr);
    EXPECT_EQ(rst_target->callers, (std::vector<std::string>{"fn_b0000_0170"}));
    EXPECT_GT(result.analyzed_instructions, 0U);
}

TEST(FunctionDiscoveryTests, ResolvesCallsIntoTheSwitchableWindowByPhysicalBank) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $4000; from fixed bank this assumes bank 1.
    bytes[0x0151U] = 0x00U;
    bytes[0x0152U] = 0x40U;
    bytes[0x0153U] = 0xC9U;
    bytes[0x4000U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto image = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(image.has_value()) << load_error.message;

    const FunctionDiscoveryResult result = discover_functions(*image);

    const FunctionInfo* banked = find_function(result, 1U, 0x4000U);
    ASSERT_NE(banked, nullptr);
    EXPECT_EQ(banked->name, "sub_b0001_4000");
    EXPECT_EQ(banked->confidence_percent, 85U);
    EXPECT_EQ(banked->callers, (std::vector<std::string>{"fn_b0000_0100"}));
}

TEST(FunctionDiscoveryTests, ReportsCancellation) {
    test::TemporaryRomFile file(make_function_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto image = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(image.has_value()) << load_error.message;
    std::stop_source cancellation;
    cancellation.request_stop();

    const FunctionDiscoveryResult result = discover_functions(*image, cancellation.get_token());

    EXPECT_TRUE(result.cancelled);
}

}  // namespace
}  // namespace tool::analysis
