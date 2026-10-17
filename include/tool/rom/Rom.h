#pragma once

#include "tool/rom/RomBank.h"
#include "tool/rom/RomHeader.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace tool::rom {

enum class RomLoadErrorCode {
    CannotOpen,
    ReadFailure,
    FileTooLarge,
    TruncatedHeader,
    MalformedHeader,
};

struct RomLoadError {
    RomLoadErrorCode code{RomLoadErrorCode::ReadFailure};
    std::string message;
};

enum class RomIssueSeverity {
    Warning,
    Error,
};

enum class RomIssueCode {
    UnsupportedCartridge,
    TruncatedRom,
    InconsistentRomSize,
    InvalidNintendoLogo,
    InvalidHeaderChecksum,
    InvalidGlobalChecksum,
    UnusedRamSizeCode,
    UnexpectedCartridgeRam,
};

struct RomIssue {
    RomIssueCode code;
    RomIssueSeverity severity;
    std::string message;
};

class Rom {
public:
    [[nodiscard]] static std::optional<Rom> load_file(
        const std::filesystem::path& path, RomLoadError& error);

    [[nodiscard]] const std::filesystem::path& path() const noexcept;
    [[nodiscard]] const RomHeader& header() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept;
    [[nodiscard]] std::size_t actual_size_bytes() const noexcept;
    [[nodiscard]] std::size_t actual_bank_count() const noexcept;
    [[nodiscard]] const std::vector<RomIssue>& issues() const noexcept;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::optional<RomBank> bank(std::uint16_t index) const noexcept;

    // The supplied bank numbers are effective physical banks. Mapper register
    // state and MBC-specific bank aliasing are modeled in a later phase.
    [[nodiscard]] std::optional<std::size_t> translate_cpu_address(
        std::uint16_t address, std::uint16_t fixed_bank = 0,
        std::uint16_t switchable_bank = 1) const noexcept;

private:
    Rom(std::filesystem::path path, std::vector<std::uint8_t> bytes,
        RomHeader header);
    void validate();

    std::filesystem::path path_;
    std::vector<std::uint8_t> bytes_;
    RomHeader header_;
    std::vector<RomIssue> issues_;
};

}  // namespace tool::rom
