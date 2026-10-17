#include "tool/memory/MemoryMap.h"

#include <algorithm>

namespace tool::memory {
namespace {

constexpr std::array<MemoryRegionDescriptor, 12> kRegions{{
    {0x0000U, 0x3FFFU, MemoryRegion::FixedRom, "ROM bank 00", "Fixed cartridge ROM window"},
    {0x4000U, 0x7FFFU, MemoryRegion::SwitchableRom, "Switchable ROM", "Mapper-selected cartridge ROM window"},
    {0x8000U, 0x9FFFU, MemoryRegion::VideoRam, "VRAM", "Video RAM; banked on CGB"},
    {0xA000U, 0xBFFFU, MemoryRegion::ExternalRam, "External RAM", "Cartridge RAM or mapper-backed storage"},
    {0xC000U, 0xCFFFU, MemoryRegion::WorkRam0, "WRAM bank 0", "Fixed work RAM bank"},
    {0xD000U, 0xDFFFU, MemoryRegion::SwitchableWorkRam, "Switchable WRAM", "Bank 1 on DMG; switchable on CGB"},
    {0xE000U, 0xFDFFU, MemoryRegion::EchoRam, "Echo RAM", "Mirror of $C000-$DDFF"},
    {0xFE00U, 0xFE9FU, MemoryRegion::Oam, "OAM", "Object attribute memory"},
    {0xFEA0U, 0xFEFFU, MemoryRegion::Unusable, "Unusable", "Unusable address range"},
    {0xFF00U, 0xFF7FU, MemoryRegion::IoRegisters, "I/O registers", "Hardware registers with device side effects"},
    {0xFF80U, 0xFFFEU, MemoryRegion::HighRam, "HRAM", "High-speed internal RAM"},
    {0xFFFFU, 0xFFFFU, MemoryRegion::InterruptEnable, "IE", "Interrupt enable register"},
}};

constexpr std::array<HardwareRegisterInfo, 33> kRegisters{{
    {0xFF00U, "P1/JOYP", "Joypad input selection and button state", true, true, true},
    {0xFF01U, "SB", "Serial transfer data", true, true, true},
    {0xFF02U, "SC", "Serial transfer control", true, true, true},
    {0xFF04U, "DIV", "Divider counter; writes reset the counter", true, true, true},
    {0xFF05U, "TIMA", "Timer counter; overflow can request an interrupt", true, true, true},
    {0xFF06U, "TMA", "Timer modulo value", true, true, true},
    {0xFF07U, "TAC", "Timer enable and clock selection", true, true, true},
    {0xFF0FU, "IF", "Interrupt request flags", true, true, true},
    {0xFF40U, "LCDC", "LCD controller enable and display configuration", true, true, true},
    {0xFF41U, "STAT", "LCD status and mode flags", true, true, true},
    {0xFF42U, "SCY", "Background vertical scroll", true, true, true},
    {0xFF43U, "SCX", "Background horizontal scroll", true, true, true},
    {0xFF44U, "LY", "Current LCD scanline; read-only counter", true, false, true},
    {0xFF45U, "LYC", "LCD scanline comparison value", true, true, true},
    {0xFF46U, "DMA", "OAM DMA source page; starts a transfer", true, true, true},
    {0xFF47U, "BGP", "Background palette mapping", true, true, true},
    {0xFF48U, "OBP0", "Object palette 0 mapping", true, true, true},
    {0xFF49U, "OBP1", "Object palette 1 mapping", true, true, true},
    {0xFF4AU, "WY", "Window vertical position", true, true, true},
    {0xFF4BU, "WX", "Window horizontal position", true, true, true},
    {0xFF4DU, "KEY1", "CGB speed switch control", true, true, true},
    {0xFF4FU, "VBK", "CGB VRAM bank selection", true, true, true},
    {0xFF50U, "BOOT", "Boot ROM disable latch", true, true, true},
    {0xFF51U, "HDMA1", "CGB VRAM DMA source high byte", true, true, true},
    {0xFF52U, "HDMA2", "CGB VRAM DMA source low byte", true, true, true},
    {0xFF53U, "HDMA3", "CGB VRAM DMA destination high byte", true, true, true},
    {0xFF54U, "HDMA4", "CGB VRAM DMA destination low byte", true, true, true},
    {0xFF55U, "HDMA5", "CGB VRAM DMA length and transfer control", true, true, true},
    {0xFF68U, "BGPI", "CGB background palette index", true, true, true},
    {0xFF69U, "BGPD", "CGB background palette data", true, true, true},
    {0xFF6AU, "OBPI", "CGB object palette index", true, true, true},
    {0xFF6BU, "OBPD", "CGB object palette data", true, true, true},
    {0xFFFFU, "IE", "Interrupt enable flags", true, true, true},
}};

}  // namespace

const std::array<MemoryRegionDescriptor, 12>& memory_region_table() noexcept {
    return kRegions;
}

const std::array<HardwareRegisterInfo, 33>& hardware_register_table() noexcept {
    return kRegisters;
}

const HardwareRegisterInfo* hardware_register_info(const std::uint16_t address) noexcept {
    const auto found = std::find_if(kRegisters.begin(), kRegisters.end(),
        [address](const HardwareRegisterInfo& item) { return item.address == address; });
    return found == kRegisters.end() ? nullptr : &*found;
}

MemoryMapping map_memory_address(const std::uint16_t address,
                                 const MemoryMapContext& context) noexcept {
    MemoryMapping result;
    result.address = address;
    result.canonical_address = address;

    if (address <= 0x3FFFU) {
        result.region = MemoryRegion::FixedRom;
        result.bank = context.fixed_rom_bank;
        result.bank_selection_known = context.mapper_state_known;
        return result;
    }
    if (address <= 0x7FFFU) {
        result.region = MemoryRegion::SwitchableRom;
        result.bank = context.switchable_rom_bank;
        result.bank_selection_known = context.mapper_state_known;
        return result;
    }
    if (address <= 0x9FFFU) {
        result.region = MemoryRegion::VideoRam;
        result.bank = context.hardware_mode == HardwareMode::Dmg
            ? std::optional<std::uint16_t>(std::uint16_t{0U})
            : (context.video_ram_bank.has_value()
                ? std::optional<std::uint16_t>(*context.video_ram_bank) : std::nullopt);
        result.bank_selection_known = context.hardware_mode != HardwareMode::Unknown;
        result.writable = true;
        return result;
    }
    if (address <= 0xBFFFU) {
        result.region = MemoryRegion::ExternalRam;
        result.bank = context.external_ram_bank;
        result.bank_selection_known = context.external_ram_bank.has_value() &&
                                      context.mapper_state_known;
        result.writable = true;
        return result;
    }
    if (address <= 0xCFFFU) {
        result.region = MemoryRegion::WorkRam0;
        result.bank = std::uint16_t{0U};
        result.bank_selection_known = true;
        result.writable = true;
        return result;
    }
    if (address <= 0xDFFFU) {
        result.region = MemoryRegion::SwitchableWorkRam;
        if (context.hardware_mode == HardwareMode::Dmg) {
            result.bank = std::uint16_t{1U};
            result.bank_selection_known = true;
        } else {
            result.bank = context.work_ram_bank.has_value()
                ? std::optional<std::uint16_t>(*context.work_ram_bank) : std::nullopt;
            result.bank_selection_known = context.hardware_mode == HardwareMode::Cgb &&
                                          result.bank.has_value();
        }
        result.writable = true;
        return result;
    }
    if (address <= 0xFDFFU) {
        result.region = MemoryRegion::EchoRam;
        result.canonical_address = static_cast<std::uint16_t>(address - 0x2000U);
        result.writable = true;
        if (result.canonical_address >= 0xD000U) {
            if (context.hardware_mode == HardwareMode::Dmg) {
                result.bank = std::uint16_t{1U};
                result.bank_selection_known = true;
            } else {
                result.bank = context.work_ram_bank.has_value()
                    ? std::optional<std::uint16_t>(*context.work_ram_bank) : std::nullopt;
                result.bank_selection_known = context.hardware_mode == HardwareMode::Cgb &&
                                              result.bank.has_value();
            }
        } else {
            result.bank = std::uint16_t{0U};
            result.bank_selection_known = true;
        }
        return result;
    }
    if (address <= 0xFE9FU) {
        result.region = MemoryRegion::Oam;
        result.writable = true;
        return result;
    }
    if (address <= 0xFEFFU) {
        result.region = MemoryRegion::Unusable;
        result.readable = true;
        return result;
    }
    if (address <= 0xFF7FU) {
        result.region = MemoryRegion::IoRegisters;
        result.writable = true;
        result.hardware_register = hardware_register_info(address);
        result.hardware_side_effect = result.hardware_register != nullptr &&
                                      result.hardware_register->hardware_side_effect;
        if (result.hardware_register != nullptr) {
            result.readable = result.hardware_register->readable;
            result.writable = result.hardware_register->writable;
        }
        return result;
    }
    if (address <= 0xFFFEU) {
        result.region = MemoryRegion::HighRam;
        result.writable = true;
        return result;
    }
    result.region = MemoryRegion::InterruptEnable;
    result.writable = true;
    result.hardware_register = hardware_register_info(address);
    result.hardware_side_effect = true;
    return result;
}

HardwareMode hardware_mode_from_cgb_flag(const std::uint8_t cgb_flag) noexcept {
    if ((cgb_flag & 0xC0U) == 0xC0U) {
        return HardwareMode::Cgb;
    }
    if ((cgb_flag & 0x80U) != 0U) {
        return HardwareMode::Unknown;
    }
    return HardwareMode::Dmg;
}

std::string_view memory_region_name(const MemoryRegion region) noexcept {
    const auto found = std::find_if(kRegions.begin(), kRegions.end(),
        [region](const MemoryRegionDescriptor& item) { return item.region == region; });
    return found == kRegions.end() ? "unknown" : found->name;
}

std::string_view hardware_mode_name(const HardwareMode mode) noexcept {
    switch (mode) {
        case HardwareMode::Dmg: return "DMG";
        case HardwareMode::Cgb: return "CGB";
        case HardwareMode::Unknown: return "unknown/compatible";
    }
    return "unknown";
}

}  // namespace tool::memory
