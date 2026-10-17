#include "tool/analysis/CrossReferences.h"

#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <stop_token>
#include <vector>

namespace tool::analysis {
namespace {

std::vector<std::uint8_t> make_xref_fixture() {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $0160
    bytes[0x0151U] = 0x60U;
    bytes[0x0152U] = 0x01U;
    bytes[0x0153U] = 0xFAU;  // LD A, [$4000]
    bytes[0x0154U] = 0x00U;
    bytes[0x0155U] = 0x40U;
    bytes[0x0156U] = 0xE0U;  // LDH [$FF00+$40], A
    bytes[0x0157U] = 0x40U;
    bytes[0x0158U] = 0xEAU;  // LD [$C000], A
    bytes[0x0159U] = 0x00U;
    bytes[0x015AU] = 0xC0U;
    bytes[0x015BU] = 0xEAU;  // LD [$2000], A (mapper control write)
    bytes[0x015CU] = 0x00U;
    bytes[0x015DU] = 0x20U;
    bytes[0x015EU] = 0xC9U;
    bytes[0x0160U] = 0xC9U;
    bytes[0x0300U] = 0x60U;  // Possible little-endian pointer to $0160.
    bytes[0x0301U] = 0x01U;
    bytes[0x4000U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    return bytes;
}

const CrossReference* find_reference(const CrossReferenceResult& result,
                                     const XrefKind kind,
                                     const std::uint16_t source_address,
                                     const XrefAddressSpace target_space,
                                     const std::uint16_t target_address) {
    const auto found = std::find_if(result.references.begin(), result.references.end(),
        [=](const CrossReference& reference) {
            return reference.kind == kind && reference.source.address == source_address &&
                   reference.target.space == target_space &&
                   reference.target.address == target_address;
        });
    return found == result.references.end() ? nullptr : &*found;
}

TEST(CrossReferencesTests, TracksCodeDataRamHardwareMapperAndFunctionReferences) {
    test::TemporaryRomFile file(make_xref_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    const CrossReferenceResult result = build_cross_references(*loaded);

    ASSERT_FALSE(result.cancelled);
    EXPECT_GT(result.functions_analyzed, 1U);
    EXPECT_GT(result.instructions_analyzed, 0U);
    const CrossReference* call = find_reference(result, XrefKind::CodeToCode, 0x0150U,
        XrefAddressSpace::Rom, 0x0160U);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->target.bank, 0U);
    EXPECT_FALSE(call->candidate);

    const CrossReference* function_call = find_reference(result,
        XrefKind::FunctionToFunction, 0x0150U, XrefAddressSpace::Rom, 0x0160U);
    ASSERT_NE(function_call, nullptr);
    EXPECT_FALSE(function_call->source_function_id.empty());
    EXPECT_FALSE(function_call->target_function_id.empty());

    const CrossReference* rom_data = find_reference(result, XrefKind::CodeToData, 0x0153U,
        XrefAddressSpace::Rom, 0x4000U);
    ASSERT_NE(rom_data, nullptr);
    EXPECT_EQ(rom_data->target.bank, 1U);
    EXPECT_EQ(rom_data->target.rom_offset, 0x4000U);

    EXPECT_NE(find_reference(result, XrefKind::CodeToHardwareRegister, 0x0156U,
        XrefAddressSpace::Hardware, 0xFF40U), nullptr);
    EXPECT_NE(find_reference(result, XrefKind::CodeToRam, 0x0158U,
        XrefAddressSpace::Ram, 0xC000U), nullptr);
    EXPECT_NE(find_reference(result, XrefKind::CodeToMapperRegister, 0x015BU,
        XrefAddressSpace::Mapper, 0x2000U), nullptr);

    const CrossReference* data_pointer = find_reference(result, XrefKind::DataToCode, 0x0300U,
        XrefAddressSpace::Rom, 0x0160U);
    ASSERT_NE(data_pointer, nullptr);
    EXPECT_TRUE(data_pointer->candidate);
    EXPECT_FALSE(data_pointer->target_function_id.empty());
}

TEST(CrossReferencesTests, RecordsPhysicalBankTransitions) {
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

    const CrossReferenceResult result = build_cross_references(*loaded);

    EXPECT_NE(find_reference(result, XrefKind::BankToBank, 0x0100U,
        XrefAddressSpace::Rom, 0x4000U), nullptr);
}

TEST(CrossReferencesTests, CanQueryTheReferenceIndexByTargetLocation) {
    test::TemporaryRomFile file(make_xref_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;
    const CrossReferenceResult result = build_cross_references(*loaded);

    const auto matches = find_references_to(result,
        {XrefAddressSpace::Hardware, std::nullopt, 0xFF40U, std::nullopt});
    ASSERT_EQ(matches.size(), 1U);
    EXPECT_EQ(matches.front()->kind, XrefKind::CodeToHardwareRegister);
    EXPECT_NE(format_cross_reference(*matches.front()).find("LCDC"), std::string::npos);
}

TEST(CrossReferencesTests, UsesFormalMapForUnusableAddressSpace) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xEAU;  // LD [$FEA0], A (unusable memory)
    bytes[0x0151U] = 0xA0U;
    bytes[0x0152U] = 0xFEU;
    bytes[0x0153U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    const CrossReferenceResult result = build_cross_references(*loaded);

    EXPECT_NE(find_reference(result, XrefKind::CodeToUnusable, 0x0150U,
        XrefAddressSpace::Unusable, 0xFEA0U), nullptr);
}

TEST(CrossReferencesTests, HonorsPreRequestedCancellation) {
    test::TemporaryRomFile file(make_xref_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;
    std::stop_source source;
    source.request_stop();

    const CrossReferenceResult result = build_cross_references(*loaded, source.get_token());

    EXPECT_TRUE(result.cancelled);
    EXPECT_TRUE(result.references.empty());
}

}  // namespace
}  // namespace tool::analysis
