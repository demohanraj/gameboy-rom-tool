#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace tool::memory {

enum class HardwareMode : std::uint8_t {
    Dmg,
    Cgb,
    Unknown,
};

enum class MemoryRegion : std::uint8_t {
    FixedRom,
    SwitchableRom,
    VideoRam,
    ExternalRam,
    WorkRam0,
    SwitchableWorkRam,
    EchoRam,
    Oam,
    Unusable,
    IoRegisters,
    HighRam,
    InterruptEnable,
};

struct MemoryRegionDescriptor {
    std::uint16_t start{};
    std::uint16_t end{};
    MemoryRegion region{MemoryRegion::FixedRom};
    std::string_view name;
    std::string_view description;
};

struct HardwareRegisterInfo {
    std::uint16_t address{};
    std::string_view name;
    std::string_view description;
    bool readable{true};
    bool writable{true};
    bool hardware_side_effect{};
};

struct MemoryMapContext {
    HardwareMode hardware_mode{HardwareMode::Unknown};
    std::optional<std::uint16_t> fixed_rom_bank{std::uint16_t{0U}};
    std::optional<std::uint16_t> switchable_rom_bank{std::uint16_t{1U}};
    std::optional<std::uint16_t> external_ram_bank;
    std::optional<std::uint8_t> video_ram_bank{std::uint8_t{0U}};
    std::optional<std::uint8_t> work_ram_bank{std::uint8_t{1U}};
    bool mapper_state_known{};
};

struct MemoryMapping {
    std::uint16_t address{};
    std::uint16_t canonical_address{};
    MemoryRegion region{MemoryRegion::FixedRom};
    std::optional<std::uint16_t> bank;
    bool bank_selection_known{};
    bool readable{true};
    bool writable{};
    bool hardware_side_effect{};
    const HardwareRegisterInfo* hardware_register{};
};

[[nodiscard]] const std::array<MemoryRegionDescriptor, 12>& memory_region_table() noexcept;
[[nodiscard]] const std::array<HardwareRegisterInfo, 33>& hardware_register_table() noexcept;
[[nodiscard]] const HardwareRegisterInfo* hardware_register_info(
    std::uint16_t address) noexcept;
[[nodiscard]] MemoryMapping map_memory_address(
    std::uint16_t address, const MemoryMapContext& context = {}) noexcept;
[[nodiscard]] HardwareMode hardware_mode_from_cgb_flag(std::uint8_t cgb_flag) noexcept;
[[nodiscard]] std::string_view memory_region_name(MemoryRegion region) noexcept;
[[nodiscard]] std::string_view hardware_mode_name(HardwareMode mode) noexcept;

}  // namespace tool::memory
