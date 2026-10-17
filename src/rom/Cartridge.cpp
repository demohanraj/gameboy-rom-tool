#include "tool/rom/Cartridge.h"

namespace tool::rom {
namespace {

constexpr Cartridge cartridge(const std::uint8_t code, const std::string_view name,
                              const MbcType mapper, const bool supported,
                              const bool ram = false, const bool battery = false,
                              const bool timer = false, const bool rumble = false,
                              const bool internal_ram = false) noexcept {
    return {code, name, mapper, supported, ram, battery, timer, rumble, internal_ram};
}

}  // namespace

Cartridge identify_cartridge(const std::uint8_t type_code) noexcept {
    switch (type_code) {
        case 0x00:
            return cartridge(type_code, "ROM ONLY", MbcType::None, true);
        case 0x01:
            return cartridge(type_code, "MBC1", MbcType::Mbc1, true);
        case 0x02:
            return cartridge(type_code, "MBC1+RAM", MbcType::Mbc1, true, true);
        case 0x03:
            return cartridge(type_code, "MBC1+RAM+BATTERY", MbcType::Mbc1, true, true, true);
        case 0x05:
            return cartridge(type_code, "MBC2", MbcType::Mbc2, true, true, false, false, false, true);
        case 0x06:
            return cartridge(type_code, "MBC2+BATTERY", MbcType::Mbc2, true, true, true, false, false, true);
        case 0x08:
            return cartridge(type_code, "ROM+RAM", MbcType::None, true, true);
        case 0x09:
            return cartridge(type_code, "ROM+RAM+BATTERY", MbcType::None, true, true, true);
        case 0x0F:
            return cartridge(type_code, "MBC3+TIMER+BATTERY", MbcType::Mbc3, true, false, true, true);
        case 0x10:
            return cartridge(type_code, "MBC3+TIMER+RAM+BATTERY", MbcType::Mbc3, true, true, true, true);
        case 0x11:
            return cartridge(type_code, "MBC3", MbcType::Mbc3, true);
        case 0x12:
            return cartridge(type_code, "MBC3+RAM", MbcType::Mbc3, true, true);
        case 0x13:
            return cartridge(type_code, "MBC3+RAM+BATTERY", MbcType::Mbc3, true, true, true);
        case 0x19:
            return cartridge(type_code, "MBC5", MbcType::Mbc5, true);
        case 0x1A:
            return cartridge(type_code, "MBC5+RAM", MbcType::Mbc5, true, true);
        case 0x1B:
            return cartridge(type_code, "MBC5+RAM+BATTERY", MbcType::Mbc5, true, true, true);
        case 0x1C:
            return cartridge(type_code, "MBC5+RUMBLE", MbcType::Mbc5, true, false, false, false, true);
        case 0x1D:
            return cartridge(type_code, "MBC5+RUMBLE+RAM", MbcType::Mbc5, true, true, false, false, true);
        case 0x1E:
            return cartridge(type_code, "MBC5+RUMBLE+RAM+BATTERY", MbcType::Mbc5, true, true, true, false, true);
        case 0x0B:
        case 0x0C:
        case 0x0D:
            return cartridge(type_code, "MMM01", MbcType::Unsupported, false,
                             type_code != 0x0B, type_code == 0x0C || type_code == 0x0D);
        case 0x20:
            return cartridge(type_code, "MBC6", MbcType::Unsupported, false, true, true);
        case 0x22:
            return cartridge(type_code, "MBC7+SENSOR+RUMBLE+RAM+BATTERY",
                             MbcType::Unsupported, false, true, true, false, true);
        case 0xFC:
            return cartridge(type_code, "POCKET CAMERA", MbcType::Unsupported, false, true, true);
        case 0xFD:
            return cartridge(type_code, "BANDAI TAMA5", MbcType::Unsupported, false, true, true, true);
        case 0xFE:
            return cartridge(type_code, "HuC3", MbcType::Unsupported, false, true, true, true);
        case 0xFF:
            return cartridge(type_code, "HuC1+RAM+BATTERY", MbcType::Unsupported, false, true, true);
        default:
            return cartridge(type_code, "Unknown/unsupported", MbcType::Unsupported, false);
    }
}

std::string_view mapper_name(const MbcType mapper) noexcept {
    switch (mapper) {
        case MbcType::None:
            return "None";
        case MbcType::Mbc1:
            return "MBC1";
        case MbcType::Mbc2:
            return "MBC2";
        case MbcType::Mbc3:
            return "MBC3";
        case MbcType::Mbc5:
            return "MBC5";
        case MbcType::Unsupported:
            return "Unsupported";
    }
    return "Unsupported";
}

}  // namespace tool::rom
