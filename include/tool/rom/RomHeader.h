#pragma once

#include "tool/rom/Cartridge.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace tool::rom {

inline constexpr std::size_t kRomBankSize = 0x4000;
inline constexpr std::size_t kRomHeaderSize = 0x150;

struct RomHeader {
    std::array<std::uint8_t, 4> entry_point{};
    std::array<std::uint8_t, 16> raw_title{};
    std::string title;
    std::array<std::uint8_t, 4> manufacturer_code{};
    bool has_manufacturer_code{};
    std::uint8_t cgb_flag{};
    std::array<std::uint8_t, 2> new_licensee_code{};
    std::uint8_t sgb_flag{};
    Cartridge cartridge;
    std::uint8_t rom_size_code{};
    std::uint32_t declared_rom_size_bytes{};
    std::uint16_t declared_rom_bank_count{};
    std::uint8_t ram_size_code{};
    std::uint32_t declared_ram_size_bytes{};
    bool ram_size_known{true};
    std::uint8_t destination_code{};
    std::uint8_t old_licensee_code{};
    std::uint8_t version_number{};
    std::uint8_t header_checksum{};
    std::uint8_t calculated_header_checksum{};
    std::uint16_t global_checksum{};
    std::uint16_t calculated_global_checksum{};
    bool header_checksum_valid{};
    bool global_checksum_valid{};
    bool nintendo_logo_valid{};

    [[nodiscard]] static std::optional<RomHeader> parse(
        std::span<const std::uint8_t> bytes, std::string& error_message);
    [[nodiscard]] static std::uint8_t calculate_header_checksum(
        std::span<const std::uint8_t> bytes) noexcept;
    [[nodiscard]] static std::uint16_t calculate_global_checksum(
        std::span<const std::uint8_t> bytes) noexcept;
};

}  // namespace tool::rom
