#include "tool/rom/Cartridge.h"
#include "tool/rom/Rom.h"
#include "tool/rom/RomHeader.h"
#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace tool::rom {
namespace {

TEST(CartridgeTests, IdentifiesSupportedMapperFamiliesAndUnknownTypes) {
    EXPECT_EQ(identify_cartridge(0x00U).mapper, MbcType::None);
    EXPECT_TRUE(identify_cartridge(0x03U).supported);
    EXPECT_TRUE(identify_cartridge(0x05U).has_internal_ram);
    EXPECT_EQ(identify_cartridge(0x10U).mapper, MbcType::Mbc3);
    EXPECT_TRUE(identify_cartridge(0x1EU).has_rumble);
    EXPECT_FALSE(identify_cartridge(0xFCU).supported);
    EXPECT_EQ(identify_cartridge(0xFCU).type_name, "POCKET CAMERA");
}

TEST(RomHeaderTests, ParsesTitleCartridgeSizesLogoAndChecksums) {
    const std::vector<std::uint8_t> bytes = test::make_test_rom(0x03U, 0x00U, 0x03U, "PHASE ONE");
    std::string error;
    const auto parsed = RomHeader::parse(bytes, error);

    ASSERT_TRUE(parsed.has_value()) << error;
    EXPECT_EQ(parsed->title, "PHASE ONE");
    EXPECT_EQ(parsed->cartridge.mapper, MbcType::Mbc1);
    EXPECT_TRUE(parsed->cartridge.has_battery);
    EXPECT_EQ(parsed->declared_rom_size_bytes, 32'768U);
    EXPECT_EQ(parsed->declared_rom_bank_count, 2U);
    EXPECT_EQ(parsed->declared_ram_size_bytes, 32U * 1024U);
    EXPECT_TRUE(parsed->nintendo_logo_valid);
    EXPECT_TRUE(parsed->header_checksum_valid);
    EXPECT_TRUE(parsed->global_checksum_valid);
}

TEST(RomHeaderTests, SupportsTheNonPowerOfTwoRomSizeCodes) {
    const std::pair<std::uint8_t, std::uint16_t> cases[] = {
        {0x52U, 72U}, {0x53U, 80U}, {0x54U, 96U},
    };
    for (const auto [code, banks] : cases) {
        std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, code);
        std::string error;
        const auto parsed = RomHeader::parse(bytes, error);
        ASSERT_TRUE(parsed.has_value()) << error;
        EXPECT_EQ(parsed->declared_rom_bank_count, banks);
    }
}

TEST(RomHeaderTests, RejectsShortAndMalformedHeaders) {
    std::string error;
    EXPECT_FALSE(RomHeader::parse(std::vector<std::uint8_t>(0x14FU), error).has_value());
    EXPECT_NE(error.find("shorter"), std::string::npos);

    std::vector<std::uint8_t> bytes = test::make_test_rom();
    bytes[0x148U] = 0x09U;
    EXPECT_FALSE(RomHeader::parse(bytes, error).has_value());
    EXPECT_NE(error.find("ROM size code"), std::string::npos);
}

TEST(RomTests, LoadsValidRomAndTranslatesAddressesWithPhysicalBanks) {
    test::TemporaryRomFile file(test::make_test_rom());
    ASSERT_TRUE(file.written());
    RomLoadError error;
    auto loaded = Rom::load_file(file.path(), error);

    ASSERT_TRUE(loaded.has_value()) << error.message;
    EXPECT_TRUE(loaded->is_valid());
    ASSERT_EQ(loaded->actual_bank_count(), 2U);
    EXPECT_EQ(loaded->translate_cpu_address(0x0100U), 0x0100U);
    EXPECT_EQ(loaded->translate_cpu_address(0x4100U), 0x4100U);
    EXPECT_EQ(loaded->translate_cpu_address(0x4100U, 0U, 1U), kRomBankSize + 0x0100U);
    EXPECT_FALSE(loaded->translate_cpu_address(0x8000U).has_value());

    const auto second_bank = loaded->bank(1U);
    ASSERT_TRUE(second_bank.has_value());
    EXPECT_EQ(second_bank->read_cpu_address(0x4000U), 1U);
    EXPECT_FALSE(loaded->bank(2U).has_value());
}

TEST(RomTests, ReportsTruncatedAndUnsupportedCartridgeFiles) {
    std::vector<std::uint8_t> truncated = test::make_test_rom();
    truncated.resize(kRomHeaderSize);
    test::TemporaryRomFile truncated_file(truncated);
    RomLoadError error;
    auto truncated_rom = Rom::load_file(truncated_file.path(), error);
    ASSERT_TRUE(truncated_rom.has_value()) << error.message;
    EXPECT_FALSE(truncated_rom->is_valid());
    ASSERT_FALSE(truncated_rom->issues().empty());
    EXPECT_EQ(truncated_rom->issues().front().code, RomIssueCode::TruncatedRom);

    test::TemporaryRomFile unsupported_file(test::make_test_rom(0xFCU));
    auto unsupported_rom = Rom::load_file(unsupported_file.path(), error);
    ASSERT_TRUE(unsupported_rom.has_value()) << error.message;
    EXPECT_FALSE(unsupported_rom->is_valid());
    EXPECT_EQ(unsupported_rom->issues().front().code, RomIssueCode::UnsupportedCartridge);
}

TEST(RomTests, TreatsBadChecksumsAndReservedRamCodeAsWarnings) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    bytes[0x134U] ^= 0x01U;
    bytes[0x149U] = 0x01U;
    test::update_fixture_checksums(bytes);
    bytes[0x14DU] ^= 0x01U;
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    RomLoadError error;
    auto loaded = Rom::load_file(file.path(), error);
    ASSERT_TRUE(loaded.has_value()) << error.message;
    EXPECT_TRUE(loaded->is_valid());
    EXPECT_FALSE(loaded->header().header_checksum_valid);
    EXPECT_FALSE(loaded->header().ram_size_known);
}

TEST(RomTests, ReturnsAnErrorForMissingFiles) {
    RomLoadError error;
    const auto loaded = Rom::load_file("tool-phase1-missing-file.gb", error);
    EXPECT_FALSE(loaded.has_value());
    EXPECT_EQ(error.code, RomLoadErrorCode::CannotOpen);
}

}  // namespace
}  // namespace tool::rom
