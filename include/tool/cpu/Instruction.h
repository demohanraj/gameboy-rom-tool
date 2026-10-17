#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tool::cpu {

inline constexpr std::uint8_t kFlagZ = 1U << 0U;
inline constexpr std::uint8_t kFlagN = 1U << 1U;
inline constexpr std::uint8_t kFlagH = 1U << 2U;
inline constexpr std::uint8_t kFlagC = 1U << 3U;
inline constexpr std::uint8_t kAllFlags = kFlagZ | kFlagN | kFlagH | kFlagC;

enum class InstructionCategory : std::uint8_t {
    Load,
    Arithmetic,
    Logical,
    Increment,
    Decrement,
    Rotate,
    Shift,
    Bit,
    Compare,
    Branch,
    Call,
    Return,
    Stack,
    Control,
    Interrupt,
    Misc,
    Illegal,
};

enum class ControlFlowType : std::uint8_t {
    Sequential,
    ConditionalBranch,
    UnconditionalBranch,
    Call,
    ConditionalCall,
    Return,
    ConditionalReturn,
    Reset,
    IndirectJump,
    IndirectCall,
    Halt,
    Stop,
    InterruptReturn,
    Unknown,
};

// Cycle counts are in T-states. Non-conditional instructions use the same
// value for taken and not_taken.
struct CycleInfo {
    std::uint8_t taken{};
    std::uint8_t not_taken{};
    bool conditional{};
};

struct Instruction {
    std::uint16_t address{};
    std::uint8_t opcode{};
    std::optional<std::uint8_t> extended_opcode;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::uint8_t length{};
    CycleInfo cycles;
    std::uint8_t flags_read{};
    std::uint8_t flags_written{};
    bool flags_behavior_known{true};
    bool reads_memory{};
    bool writes_memory{};
    bool memory_behavior_known{true};
    InstructionCategory category{InstructionCategory::Misc};
    ControlFlowType control_flow{ControlFlowType::Sequential};
    std::optional<std::uint16_t> branch_target;
    bool legal{true};
};

[[nodiscard]] std::string_view instruction_category_name(InstructionCategory category) noexcept;
[[nodiscard]] std::string_view control_flow_name(ControlFlowType type) noexcept;
[[nodiscard]] std::string format_flag_mask(std::uint8_t flags);
[[nodiscard]] std::string format_instruction(const Instruction& instruction);

}  // namespace tool::cpu
