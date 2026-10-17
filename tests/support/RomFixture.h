#pragma once

#include "tool/rom/RomHeader.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace tool::test {

inline constexpr std::array<std::uint8_t, 48> kFixtureLogo{
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B,
    0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
    0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC,
    0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
};

inline void update_fixture_checksums(std::vector<std::uint8_t>& bytes) {
    bytes[0x14DU] = tool::rom::RomHeader::calculate_header_checksum(bytes);
    std::uint32_t sum = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0x14EU && index != 0x14FU) {
            sum += bytes[index];
        }
    }
    bytes[0x14EU] = static_cast<std::uint8_t>((sum >> 8U) & 0xFFU);
    bytes[0x14FU] = static_cast<std::uint8_t>(sum & 0xFFU);
}

inline std::vector<std::uint8_t> make_test_rom(const std::uint8_t cartridge_type = 0x01U,
                                               const std::uint8_t rom_size_code = 0x00U,
                                               const std::uint8_t ram_size_code = 0x00U,
                                               const std::string& title = "TEST ROM") {
    std::vector<std::uint8_t> bytes(2U * tool::rom::kRomBankSize, 0U);
    std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(tool::rom::kRomBankSize),
              bytes.end(), 1U);
    std::copy(kFixtureLogo.begin(), kFixtureLogo.end(), bytes.begin() + 0x104);
    std::copy_n(title.begin(), std::min(title.size(), std::size_t{16}), bytes.begin() + 0x134);
    bytes[0x143U] = 0x00U;
    bytes[0x147U] = cartridge_type;
    bytes[0x148U] = rom_size_code;
    bytes[0x149U] = ram_size_code;
    bytes[0x14AU] = 0x01U;
    update_fixture_checksums(bytes);
    return bytes;
}

class TemporaryRomFile {
public:
    explicit TemporaryRomFile(const std::vector<std::uint8_t>& bytes) {
        static std::atomic<unsigned long long> sequence{0};
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path() /
                ("tool-phase1-" + std::to_string(stamp) + "-" +
                 std::to_string(sequence.fetch_add(1)) + ".gb");
        std::ofstream file(path_, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()));
            written_ = static_cast<bool>(file);
        }
    }

    ~TemporaryRomFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    TemporaryRomFile(const TemporaryRomFile&) = delete;
    TemporaryRomFile& operator=(const TemporaryRomFile&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] bool written() const noexcept { return written_; }

private:
    std::filesystem::path path_;
    bool written_{};
};

}  // namespace tool::test
