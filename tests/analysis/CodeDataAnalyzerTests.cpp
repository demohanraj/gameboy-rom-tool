#include "tool/analysis/CodeDataAnalyzer.h"
#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tool::analysis {
namespace {

std::vector<std::uint8_t> make_reachability_fixture() {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;  // RET from each interrupt vector.
    }

    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $0160
    bytes[0x0151U] = 0x60U;
    bytes[0x0152U] = 0x01U;
    bytes[0x0153U] = 0x20U;  // JR NZ, $0157
    bytes[0x0154U] = 0x02U;
    bytes[0x0155U] = 0xC9U;
    bytes[0x0157U] = 0xC9U;
    bytes[0x0160U] = 0xC9U;

    std::fill(bytes.begin() + 0x0180, bytes.begin() + 0x01A0, 0x00U);
    for (std::size_t index = 0U; index < 48U; ++index) {
        bytes[0x0300U + index] = static_cast<std::uint8_t>(0x40U + (index % 7U));
    }
    test::update_fixture_checksums(bytes);
    return bytes;
}

const ClassificationRecord* record_containing(
    const std::vector<ClassificationRecord>& records, const std::size_t offset) {
    const auto found = std::find_if(records.begin(), records.end(), [offset](const auto& record) {
        return offset >= record.rom_offset && offset < record.rom_offset + record.length;
    });
    return found == records.end() ? nullptr : &*found;
}

TEST(CodeDataAnalyzerTests, FollowsBranchesAndCallsAndLeavesOtherRegionsUncertain) {
    test::TemporaryRomFile file(make_reachability_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    std::vector<ClassificationRecord> records;
    const ReachabilityStats stats = analyze_reachable_code(
        *loaded, [&records](const ClassificationRecord& record) {
            records.push_back(record);
            return true;
        });

    ASSERT_FALSE(stats.stopped_early);
    const ClassificationRecord* reset = record_containing(records, 0x0100U);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->classification, RegionClassification::Code);
    EXPECT_EQ(reset->confidence_percent, 100U);
    EXPECT_EQ(reset->evidence, AnalysisEvidence::ResetEntry);
    ASSERT_TRUE(reset->instruction.has_value());
    EXPECT_EQ(reset->instruction->mnemonic, "JP");

    const ClassificationRecord* call_target = record_containing(records, 0x0150U);
    ASSERT_NE(call_target, nullptr);
    EXPECT_EQ(call_target->classification, RegionClassification::Code);
    EXPECT_EQ(call_target->evidence, AnalysisEvidence::DirectBranch);
    const ClassificationRecord* fallthrough = record_containing(records, 0x0153U);
    ASSERT_NE(fallthrough, nullptr);
    EXPECT_EQ(fallthrough->classification, RegionClassification::Code);
    const ClassificationRecord* subroutine = record_containing(records, 0x0160U);
    ASSERT_NE(subroutine, nullptr);
    EXPECT_EQ(subroutine->classification, RegionClassification::Code);
    EXPECT_EQ(subroutine->evidence, AnalysisEvidence::DirectCall);

    const ClassificationRecord* cartridge_header = record_containing(records, 0x0120U);
    ASSERT_NE(cartridge_header, nullptr);
    EXPECT_EQ(cartridge_header->classification, RegionClassification::Data);
    EXPECT_EQ(cartridge_header->evidence, AnalysisEvidence::CartridgeHeader);

    const ClassificationRecord* fill = record_containing(records, 0x0180U);
    ASSERT_NE(fill, nullptr);
    EXPECT_EQ(fill->classification, RegionClassification::PossibleData);
    EXPECT_EQ(fill->confidence_percent, 60U);

    const ClassificationRecord* unvisited = record_containing(records, 0x0300U);
    ASSERT_NE(unvisited, nullptr);
    EXPECT_EQ(unvisited->classification, RegionClassification::Unknown);
    EXPECT_GT(stats.code_instructions, 0U);
    EXPECT_GT(stats.data_regions, 0U);
    EXPECT_GT(stats.possible_data_regions, 0U);
    EXPECT_GT(stats.unknown_regions, 0U);
}

TEST(CodeDataAnalyzerTests, MarksOverlappingInstructionTargetsAsPossibleCode) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0x18U;  // JR -1 targets its own immediate byte.
    bytes[0x0151U] = 0xFFU;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    std::vector<ClassificationRecord> records;
    const ReachabilityStats stats = analyze_reachable_code(
        *loaded, [&records](const ClassificationRecord& record) {
        records.push_back(record);
        return true;
    });
    EXPECT_FALSE(stats.stopped_early);

    const auto found = std::find_if(records.begin(), records.end(), [](const auto& record) {
        return record.rom_offset == 0x0151U;
    });
    ASSERT_NE(found, records.end());
    EXPECT_EQ(found->classification, RegionClassification::PossibleCode);
    EXPECT_EQ(found->evidence, AnalysisEvidence::InstructionOverlap);
}

TEST(CodeDataAnalyzerTests, UsesDefaultSwitchBankAssumptionForFixedBankTransfer) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $4000
    bytes[0x0101U] = 0x00U;
    bytes[0x0102U] = 0x40U;
    bytes[0x4000U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    std::vector<ClassificationRecord> records;
    const ReachabilityStats stats = analyze_reachable_code(
        *loaded, [&records](const ClassificationRecord& record) {
        records.push_back(record);
        return true;
    });
    EXPECT_FALSE(stats.stopped_early);

    const ClassificationRecord* target = record_containing(records, 0x4000U);
    ASSERT_NE(target, nullptr);
    EXPECT_EQ(target->bank, 1U);
    EXPECT_EQ(target->cpu_address, 0x4000U);
    EXPECT_EQ(target->classification, RegionClassification::Code);
    EXPECT_EQ(target->confidence_percent, 85U);
}

}  // namespace
}  // namespace tool::analysis
