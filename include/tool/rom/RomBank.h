#pragma once

#include "tool/rom/RomHeader.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace tool::rom {

// A physical ROM bank. The bank index is part of its identity because the same
// CPU address can refer to different file bytes after a cartridge bank switch.
class RomBank {
public:
    RomBank(std::uint16_t index, std::size_t file_offset,
            std::span<const std::uint8_t> bytes) noexcept;

    [[nodiscard]] std::uint16_t index() const noexcept;
    [[nodiscard]] std::size_t file_offset() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept;
    [[nodiscard]] std::optional<std::size_t> file_offset_for_cpu_address(
        std::uint16_t address) const noexcept;
    [[nodiscard]] std::optional<std::uint8_t> read_cpu_address(
        std::uint16_t address) const noexcept;

private:
    std::uint16_t index_;
    std::size_t file_offset_;
    std::span<const std::uint8_t> bytes_;
};

}  // namespace tool::rom
