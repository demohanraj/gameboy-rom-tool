#pragma once

#include "tool/cpu/Instruction.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace tool::cpu {

struct OpcodeMetadata {
    std::uint8_t opcode{};
    bool cb_prefixed{};
    std::uint8_t length{1};
    CycleInfo cycles;
    std::string mnemonic;
    std::string operands;
    InstructionCategory category{InstructionCategory::Illegal};
    std::uint8_t flags_read{};
    std::uint8_t flags_written{};
    bool flags_behavior_known{};
    bool reads_memory{};
    bool writes_memory{};
    bool memory_behavior_known{};
    ControlFlowType control_flow{ControlFlowType::Unknown};
    std::optional<std::uint16_t> fixed_branch_target;
    bool legal{};
};

using OpcodeTable = std::array<OpcodeMetadata, 256>;

[[nodiscard]] const OpcodeTable& base_opcode_table() noexcept;
[[nodiscard]] const OpcodeTable& cb_opcode_table() noexcept;
[[nodiscard]] const OpcodeMetadata& base_opcode_metadata(std::uint8_t opcode) noexcept;
[[nodiscard]] const OpcodeMetadata& cb_opcode_metadata(std::uint8_t opcode) noexcept;

}  // namespace tool::cpu
