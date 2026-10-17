#pragma once

#include "tool/analysis/FunctionDiscovery.h"
#include "tool/cpu/SM83.h"
#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace tool::analysis {

enum class CFGEdgeKind : std::uint8_t {
    Fallthrough,
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Call,
    Return,
    Indirect,
};

enum class ConditionOutcome : std::uint8_t {
    Taken,
    NotTaken,
};

struct CFGEdge {
    std::string source_block_id;
    CFGEdgeKind kind{CFGEdgeKind::Fallthrough};
    std::optional<std::string> target_block_id;
    std::optional<std::string> target_function_id;
    std::optional<std::uint16_t> target_bank;
    std::optional<std::uint16_t> target_address;
    std::optional<ConditionOutcome> condition_outcome;
};

struct BasicBlock {
    std::string id;
    std::uint16_t bank{};
    std::uint16_t start_address{};
    std::size_t start_rom_offset{};
    std::vector<cpu::Instruction> instructions;
    std::optional<cpu::DecodeErrorCode> decode_error;
};

struct ControlFlowGraph {
    std::string function_id;
    std::string function_name;
    std::string entry_block_id;
    std::vector<BasicBlock> blocks;
    std::vector<CFGEdge> edges;
};

struct ControlFlowGraphResult {
    std::vector<ControlFlowGraph> graphs;
    std::size_t instructions_analyzed{};
    bool cancelled{};
};

// Builds one intraprocedural graph per discovered function. Direct calls point
// to their discovered callee and have a separate return-continuation edge.
[[nodiscard]] ControlFlowGraphResult build_control_flow_graphs(
    const rom::Rom& image, const std::vector<FunctionInfo>& functions,
    std::stop_token stop_token = {});

[[nodiscard]] std::string_view cfg_edge_kind_name(CFGEdgeKind kind) noexcept;
[[nodiscard]] std::string_view condition_outcome_name(ConditionOutcome outcome) noexcept;
[[nodiscard]] std::string format_control_flow_graphs_as_dot(
    const ControlFlowGraphResult& result);

}  // namespace tool::analysis
