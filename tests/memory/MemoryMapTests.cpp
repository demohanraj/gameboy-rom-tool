#include "tool/memory/MemoryMap.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <utility>

namespace tool::memory {
namespace {

TEST(MemoryMapTests, MapsTheCompleteGameBoyAddressSpace) {
    constexpr std::array<std::pair<std::uint16_t, MemoryRegion>, 12> cases{{
        {0x0000U, MemoryRegion::FixedRom},
        {0x4000U, MemoryRegion::SwitchableRom},
        {0x8000U, MemoryRegion::VideoRam},
        {0xA000U, MemoryRegion::ExternalRam},
        {0xC000U, MemoryRegion::WorkRam0},
        {0xD000U, MemoryRegion::SwitchableWorkRam},
        {0xE000U, MemoryRegion::EchoRam},
        {0xFE00U, MemoryRegion::Oam},
        {0xFEA0U, MemoryRegion::Unusable},
        {0xFF00U, MemoryRegion::IoRegisters},
        {0xFF80U, MemoryRegion::HighRam},
        {0xFFFFU, MemoryRegion::InterruptEnable},
    }};
    for (const auto& [address, region] : cases) {
        EXPECT_EQ(map_memory_address(address).region, region) << std::hex << address;
    }
}

TEST(MemoryMapTests, ResolvesExplicitBankContextAndEchoAliases) {
    MemoryMapContext context;
    context.hardware_mode = HardwareMode::Cgb;
    context.fixed_rom_bank = 0U;
    context.switchable_rom_bank = 7U;
    context.external_ram_bank = 2U;
    context.video_ram_bank = 1U;
    context.work_ram_bank = 3U;
    context.mapper_state_known = true;

    EXPECT_EQ(map_memory_address(0x4000U, context).bank, 7U);
    EXPECT_EQ(map_memory_address(0x8000U, context).bank, 1U);
    EXPECT_EQ(map_memory_address(0xA000U, context).bank, 2U);
    EXPECT_EQ(map_memory_address(0xD000U, context).bank, 3U);
    const MemoryMapping echo = map_memory_address(0xFDFFU, context);
    EXPECT_EQ(echo.region, MemoryRegion::EchoRam);
    EXPECT_EQ(echo.canonical_address, 0xDDFFU);
    EXPECT_EQ(echo.bank, 3U);
}

TEST(MemoryMapTests, KeepsUnknownCgbAndDmgWramSemanticsExplicit) {
    const MemoryMapping unknown = map_memory_address(0xD123U);
    EXPECT_EQ(unknown.region, MemoryRegion::SwitchableWorkRam);
    EXPECT_FALSE(unknown.bank_selection_known);

    MemoryMapContext dmg;
    dmg.hardware_mode = HardwareMode::Dmg;
    const MemoryMapping known_dmg = map_memory_address(0xD123U, dmg);
    EXPECT_EQ(known_dmg.bank, 1U);
    EXPECT_TRUE(known_dmg.bank_selection_known);

    EXPECT_EQ(hardware_mode_from_cgb_flag(0x00U), HardwareMode::Dmg);
    EXPECT_EQ(hardware_mode_from_cgb_flag(0x80U), HardwareMode::Unknown);
    EXPECT_EQ(hardware_mode_from_cgb_flag(0xC0U), HardwareMode::Cgb);
}

TEST(MemoryMapTests, DescribesHardwareRegisterPermissionsAndSideEffects) {
    const HardwareRegisterInfo* div = hardware_register_info(0xFF04U);
    ASSERT_NE(div, nullptr);
    EXPECT_EQ(div->name, "DIV");
    EXPECT_TRUE(div->writable);
    EXPECT_TRUE(div->hardware_side_effect);

    const MemoryMapping ly = map_memory_address(0xFF44U);
    ASSERT_NE(ly.hardware_register, nullptr);
    EXPECT_EQ(ly.hardware_register->name, "LY");
    EXPECT_FALSE(ly.writable);

    const HardwareRegisterInfo* ie = hardware_register_info(0xFFFFU);
    ASSERT_NE(ie, nullptr);
    EXPECT_EQ(ie->name, "IE");
}

}  // namespace
}  // namespace tool::memory
