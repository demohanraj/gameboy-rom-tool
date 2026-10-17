#include "tool/rom/Rom.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <limits>
#include <new>
#include <string>
#include <utility>

namespace tool::rom {
namespace {

constexpr std::uintmax_t kMaximumRomFileSize = 64U * 1024U * 1024U;

void add_issue(std::vector<RomIssue>& issues, const RomIssueCode code,
               const RomIssueSeverity severity, std::string message) {
    issues.push_back({code, severity, std::move(message)});
}

}  // namespace

std::optional<Rom> Rom::load_file(const std::filesystem::path& path, RomLoadError& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = {RomLoadErrorCode::CannotOpen, "could not open ROM file: " + path.string()};
        return std::nullopt;
    }

    const std::streampos end = input.tellg();
    if (end < std::streampos{0}) {
        error = {RomLoadErrorCode::ReadFailure, "could not determine the ROM file size"};
        return std::nullopt;
    }
    const auto file_size = static_cast<std::uintmax_t>(end);
    if (file_size > kMaximumRomFileSize ||
        file_size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        error = {RomLoadErrorCode::FileTooLarge, "ROM file exceeds the 64 MiB safety limit"};
        return std::nullopt;
    }
    if (file_size < kRomHeaderSize) {
        error = {RomLoadErrorCode::TruncatedHeader,
                 "ROM file is shorter than the complete 0x150-byte cartridge header"};
        return std::nullopt;
    }

    try {
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(file_size));
        input.seekg(0, std::ios::beg);
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input || input.gcount() != static_cast<std::streamsize>(bytes.size())) {
            error = {RomLoadErrorCode::ReadFailure, "failed while reading the complete ROM file"};
            return std::nullopt;
        }

        std::string parse_error;
        auto header = RomHeader::parse(bytes, parse_error);
        if (!header.has_value()) {
            error = {RomLoadErrorCode::MalformedHeader, std::move(parse_error)};
            return std::nullopt;
        }
        error = {};
        return Rom(path, std::move(bytes), std::move(*header));
    } catch (const std::bad_alloc&) {
        error = {RomLoadErrorCode::FileTooLarge, "not enough memory to load the ROM file"};
        return std::nullopt;
    }
}

Rom::Rom(std::filesystem::path path, std::vector<std::uint8_t> bytes, RomHeader header)
    : path_(std::move(path)), bytes_(std::move(bytes)), header_(std::move(header)) {
    validate();
}

void Rom::validate() {
    if (!header_.cartridge.supported) {
        add_issue(issues_, RomIssueCode::UnsupportedCartridge, RomIssueSeverity::Error,
                  "unsupported cartridge type 0x" + [&] {
                      constexpr char digits[] = "0123456789ABCDEF";
                      std::string value(2, '0');
                      value[0] = digits[header_.cartridge.type_code >> 4U];
                      value[1] = digits[header_.cartridge.type_code & 0x0FU];
                      return value;
                  }() + " (" + std::string(header_.cartridge.type_name) + ")");
    }
    if (actual_size_bytes() < header_.declared_rom_size_bytes) {
        add_issue(issues_, RomIssueCode::TruncatedRom, RomIssueSeverity::Error,
                  "ROM file is smaller than the size declared in its cartridge header");
    } else if (actual_size_bytes() != header_.declared_rom_size_bytes) {
        add_issue(issues_, RomIssueCode::InconsistentRomSize, RomIssueSeverity::Error,
                  "ROM file size does not match the size declared in its cartridge header");
    }
    if (!header_.nintendo_logo_valid) {
        add_issue(issues_, RomIssueCode::InvalidNintendoLogo, RomIssueSeverity::Warning,
                  "Nintendo logo bytes in the header do not match the documented logo");
    }
    if (!header_.header_checksum_valid) {
        add_issue(issues_, RomIssueCode::InvalidHeaderChecksum, RomIssueSeverity::Warning,
                  "header checksum does not match the calculated value");
    }
    if (!header_.global_checksum_valid) {
        add_issue(issues_, RomIssueCode::InvalidGlobalChecksum, RomIssueSeverity::Warning,
                  "global checksum does not match the calculated value");
    }
    if (!header_.ram_size_known) {
        add_issue(issues_, RomIssueCode::UnusedRamSizeCode, RomIssueSeverity::Warning,
                  "RAM size code is reserved or unsupported; its size is unknown");
    }
    if ((!header_.cartridge.has_ram || header_.cartridge.has_internal_ram) &&
        header_.declared_ram_size_bytes > 0U) {
        add_issue(issues_, RomIssueCode::UnexpectedCartridgeRam, RomIssueSeverity::Warning,
                  "header declares external RAM for a cartridge type that does not use it");
    }
}

const std::filesystem::path& Rom::path() const noexcept {
    return path_;
}

const RomHeader& Rom::header() const noexcept {
    return header_;
}

std::span<const std::uint8_t> Rom::bytes() const noexcept {
    return bytes_;
}

std::size_t Rom::actual_size_bytes() const noexcept {
    return bytes_.size();
}

std::size_t Rom::actual_bank_count() const noexcept {
    return (bytes_.size() + kRomBankSize - 1U) / kRomBankSize;
}

const std::vector<RomIssue>& Rom::issues() const noexcept {
    return issues_;
}

bool Rom::is_valid() const noexcept {
    return std::none_of(issues_.begin(), issues_.end(), [](const RomIssue& issue) {
        return issue.severity == RomIssueSeverity::Error;
    });
}

std::optional<RomBank> Rom::bank(const std::uint16_t index) const noexcept {
    if (static_cast<std::size_t>(index) >= actual_bank_count()) {
        return std::nullopt;
    }
    const std::size_t offset = static_cast<std::size_t>(index) * kRomBankSize;
    const std::size_t length = std::min(kRomBankSize, bytes_.size() - offset);
    return RomBank(index, offset, std::span<const std::uint8_t>(bytes_).subspan(offset, length));
}

std::optional<std::size_t> Rom::translate_cpu_address(
    const std::uint16_t address, const std::uint16_t fixed_bank,
    const std::uint16_t switchable_bank) const noexcept {
    if (address <= 0x3FFFU) {
        const auto selected_bank = bank(fixed_bank);
        return selected_bank.has_value() ? selected_bank->file_offset_for_cpu_address(address)
                                         : std::nullopt;
    }
    if (address <= 0x7FFFU) {
        const auto selected_bank = bank(switchable_bank);
        return selected_bank.has_value() ? selected_bank->file_offset_for_cpu_address(address)
                                         : std::nullopt;
    }
    return std::nullopt;
}

}  // namespace tool::rom
