#include "tool/rom/RomBank.h"

namespace tool::rom {

RomBank::RomBank(const std::uint16_t index, const std::size_t file_offset,
                 const std::span<const std::uint8_t> bytes) noexcept
    : index_(index), file_offset_(file_offset), bytes_(bytes) {}

std::uint16_t RomBank::index() const noexcept {
    return index_;
}

std::size_t RomBank::file_offset() const noexcept {
    return file_offset_;
}

std::span<const std::uint8_t> RomBank::bytes() const noexcept {
    return bytes_;
}

std::optional<std::size_t> RomBank::file_offset_for_cpu_address(
    const std::uint16_t address) const noexcept {
    if (address > 0x7FFFU) {
        return std::nullopt;
    }
    const std::size_t offset = static_cast<std::size_t>(address & 0x3FFFU);
    if (offset >= bytes_.size()) {
        return std::nullopt;
    }
    return file_offset_ + offset;
}

std::optional<std::uint8_t> RomBank::read_cpu_address(
    const std::uint16_t address) const noexcept {
    const auto offset = file_offset_for_cpu_address(address);
    if (!offset.has_value()) {
        return std::nullopt;
    }
    return bytes_[*offset - file_offset_];
}

}  // namespace tool::rom
