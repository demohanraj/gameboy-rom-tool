#pragma once

#include <cstdint>
#include <string_view>

namespace tool::rom {

enum class MbcType : std::uint8_t {
    None,
    Mbc1,
    Mbc2,
    Mbc3,
    Mbc5,
    Unsupported,
};

struct Cartridge {
    std::uint8_t type_code{};
    std::string_view type_name{"Unknown"};
    MbcType mapper{MbcType::Unsupported};
    bool supported{};
    bool has_ram{};
    bool has_battery{};
    bool has_timer{};
    bool has_rumble{};
    bool has_internal_ram{};
};

[[nodiscard]] Cartridge identify_cartridge(std::uint8_t type_code) noexcept;
[[nodiscard]] std::string_view mapper_name(MbcType mapper) noexcept;

}  // namespace tool::rom
