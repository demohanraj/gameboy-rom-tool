#include "tool/rom/RomHeader.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <span>

namespace tool::rom {
namespace {

constexpr std::size_t kEntryPointOffset = 0x100;
constexpr std::size_t kLogoOffset = 0x104;
constexpr std::size_t kTitleOffset = 0x134;
constexpr std::size_t kCgbFlagOffset = 0x143;
constexpr std::size_t kCartridgeTypeOffset = 0x147;
constexpr std::size_t kRomSizeOffset = 0x148;
constexpr std::size_t kRamSizeOffset = 0x149;
constexpr std::size_t kHeaderChecksumOffset = 0x14D;
constexpr std::size_t kGlobalChecksumOffset = 0x14E;
constexpr std::size_t kGlobalChecksumEnd = 0x150;

constexpr std::array<std::uint8_t, 48> kNintendoLogo{
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B,
    0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
    0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC,
    0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
};

std::optional<std::uint32_t> rom_size_for_code(const std::uint8_t code) noexcept {
    if (code <= 0x08) {
        return static_cast<std::uint32_t>(32'768U << code);
    }
    switch (code) {
        case 0x52:
            return 72U * static_cast<std::uint32_t>(kRomBankSize);
        case 0x53:
            return 80U * static_cast<std::uint32_t>(kRomBankSize);
        case 0x54:
            return 96U * static_cast<std::uint32_t>(kRomBankSize);
        default:
            return std::nullopt;
    }
}

std::optional<std::uint32_t> ram_size_for_code(const std::uint8_t code) noexcept {
    switch (code) {
        case 0x00:
            return 0U;
        case 0x02:
            return 8U * 1024U;
        case 0x03:
            return 32U * 1024U;
        case 0x04:
            return 128U * 1024U;
        case 0x05:
            return 64U * 1024U;
        default:
            return std::nullopt;
    }
}

std::uint16_t read_u16(const std::span<const std::uint8_t> bytes,
                       const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U]));
}

}  // namespace

std::optional<RomHeader> RomHeader::parse(const std::span<const std::uint8_t> bytes,
                                         std::string& error_message) {
    if (bytes.size() < kRomHeaderSize) {
        error_message = "ROM is shorter than the complete 0x150-byte cartridge header";
        return std::nullopt;
    }

    const auto declared_size = rom_size_for_code(bytes[kRomSizeOffset]);
    if (!declared_size.has_value()) {
        error_message = "unsupported or malformed ROM size code in cartridge header";
        return std::nullopt;
    }

    RomHeader header;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(kEntryPointOffset),
                header.entry_point.size(), header.entry_point.begin());
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(kTitleOffset),
                header.raw_title.size(), header.raw_title.begin());
    header.cgb_flag = bytes[kCgbFlagOffset];

    const std::size_t title_length = (header.cgb_flag & 0x80U) != 0U ? 11U : 16U;
    for (std::size_t index = 0; index < title_length; ++index) {
        const auto character = static_cast<unsigned char>(header.raw_title[index]);
        if (character == 0U || character == 0xFFU) {
            break;
        }
        if (std::isprint(character) == 0) {
            header.title.push_back('?');
        } else {
            header.title.push_back(static_cast<char>(character));
        }
    }
    while (!header.title.empty() && header.title.back() == ' ') {
        header.title.pop_back();
    }

    if ((header.cgb_flag & 0x80U) != 0U) {
        std::copy_n(bytes.begin() + 0x13FU, header.manufacturer_code.size(),
                    header.manufacturer_code.begin());
        header.has_manufacturer_code = true;
    }
    header.new_licensee_code = {bytes[0x144U], bytes[0x145U]};
    header.sgb_flag = bytes[0x146U];
    header.cartridge = identify_cartridge(bytes[kCartridgeTypeOffset]);
    header.rom_size_code = bytes[kRomSizeOffset];
    header.declared_rom_size_bytes = *declared_size;
    header.declared_rom_bank_count = static_cast<std::uint16_t>(
        *declared_size / static_cast<std::uint32_t>(kRomBankSize));
    header.ram_size_code = bytes[kRamSizeOffset];
    const auto declared_ram_size = ram_size_for_code(header.ram_size_code);
    if (declared_ram_size.has_value()) {
        header.declared_ram_size_bytes = *declared_ram_size;
    } else {
        header.ram_size_known = false;
    }
    header.destination_code = bytes[0x14AU];
    header.old_licensee_code = bytes[0x14BU];
    header.version_number = bytes[0x14CU];
    header.header_checksum = bytes[kHeaderChecksumOffset];
    header.calculated_header_checksum = calculate_header_checksum(bytes);
    header.header_checksum_valid = header.header_checksum == header.calculated_header_checksum;
    header.global_checksum = read_u16(bytes, kGlobalChecksumOffset);
    header.calculated_global_checksum = calculate_global_checksum(bytes);
    header.global_checksum_valid = header.global_checksum == header.calculated_global_checksum;

    header.nintendo_logo_valid = std::equal(
        kNintendoLogo.begin(), kNintendoLogo.end(),
        bytes.begin() + static_cast<std::ptrdiff_t>(kLogoOffset));
    error_message.clear();
    return header;
}

std::uint8_t RomHeader::calculate_header_checksum(
    const std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < kRomHeaderSize) {
        return 0;
    }
    std::uint8_t checksum = 0;
    for (std::size_t index = 0x134U; index <= 0x14CU; ++index) {
        checksum = static_cast<std::uint8_t>(checksum - bytes[index] - 1U);
    }
    return checksum;
}

std::uint16_t RomHeader::calculate_global_checksum(
    const std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t checksum = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0x14EU && index != 0x14FU) {
            checksum += bytes[index];
        }
    }
    return static_cast<std::uint16_t>(checksum & 0xFFFFU);
}

}  // namespace tool::rom
