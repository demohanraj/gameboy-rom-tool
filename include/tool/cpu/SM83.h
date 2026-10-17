#pragma once

#include "tool/cpu/Instruction.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace tool::cpu {

enum class DecodeErrorCode : std::uint8_t {
    None,
    NoOpcode,
    MissingCbOpcode,
    TruncatedInstruction,
};

struct DecodeResult {
    std::optional<Instruction> instruction;
    DecodeErrorCode error{DecodeErrorCode::None};
    std::size_t required_bytes{};
    std::size_t available_bytes{};

    [[nodiscard]] bool success() const noexcept { return instruction.has_value(); }
};

// Decodes one instruction at address. The byte span begins at that address;
// additional bytes after the decoded instruction are ignored.
[[nodiscard]] DecodeResult decode_sm83_instruction(
    std::span<const std::uint8_t> bytes, std::uint16_t address);

}  // namespace tool::cpu
