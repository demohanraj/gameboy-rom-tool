#pragma once

#include "tool/analysis/ControlFlowGraph.h"
#include "tool/cpu/Instruction.h"
#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace tool::ir {

// Phase 9 preserves decoded machine instructions in a structured IR. It does
// not yet expand opcodes into CPU-state operations; that is Phase 10.
enum class IROperationKind : std::uint8_t {
    MachineOpcode,
    DecodeFailure,
};

struct IRSourceLocation {
    std::uint16_t bank{};
    std::uint16_t cpu_address{};
    std::size_t rom_offset{};
};

struct IRInstruction {
    IROperationKind kind{IROperationKind::MachineOpcode};
    IRSourceLocation source;
    std::uint8_t opcode{};
    std::optional<std::uint8_t> extended_opcode;
    std::vector<std::uint8_t> encoding;
    cpu::InstructionCategory category{cpu::InstructionCategory::Misc};
    cpu::ControlFlowType control_flow{cpu::ControlFlowType::Unknown};
    cpu::CycleInfo cycles;
    std::uint8_t flags_read{};
    std::uint8_t flags_written{};
    bool flags_behavior_known{};
    bool reads_memory{};
    bool writes_memory{};
    bool memory_behavior_known{};
    bool legal{};
    std::optional<cpu::DecodeErrorCode> decode_error;
    std::string mnemonic;
    std::string operands;
};

struct IRBasicBlock {
    std::string id;
    std::uint16_t bank{};
    std::uint16_t start_address{};
    std::size_t start_rom_offset{};
    std::vector<IRInstruction> instructions;
    std::vector<analysis::CFGEdge> successors;
};

struct IRFunction {
    std::string id;
    std::string name;
    std::string entry_block_id;
    std::vector<IRBasicBlock> blocks;
};

struct IRModule {
    std::vector<IRFunction> functions;
    std::size_t instruction_count{};
    std::size_t basic_block_count{};
    std::size_t edge_count{};
    std::size_t decode_failure_count{};
    bool cancelled{};
};

[[nodiscard]] IRModule build_ir(const rom::Rom& image,
                                std::stop_token stop_token = {});
[[nodiscard]] std::string_view ir_operation_kind_name(IROperationKind kind) noexcept;
[[nodiscard]] std::string format_ir_instruction(const IRInstruction& instruction);
[[nodiscard]] std::string format_ir_module(const IRModule& module);

}  // namespace tool::ir
