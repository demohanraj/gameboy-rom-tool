#include "tool/analysis/ControlFlowGraph.h"

#include "tool/cpu/SM83.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tool::analysis {
namespace {

using Location = std::pair<std::uint16_t, std::uint16_t>;

constexpr std::size_t kHeaderDataBegin = 0x0104U;
constexpr std::size_t kHeaderDataEnd = 0x0150U;

struct BankLocation {
    std::uint16_t bank{};
};

struct TemporaryEdge {
    CFGEdgeKind kind{CFGEdgeKind::Fallthrough};
    std::optional<Location> target;
    bool target_is_local{};
    std::optional<std::string> target_function_id;
    std::optional<ConditionOutcome> condition_outcome;
};

struct InstructionNode {
    std::uint16_t bank{};
    std::uint16_t address{};
    std::size_t rom_offset{};
    std::optional<cpu::Instruction> instruction;
    std::optional<cpu::DecodeErrorCode> decode_error;
    std::vector<TemporaryEdge> edges;
};

std::string format_hex(const std::uint16_t value) {
    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0') << std::setw(4) << value;
    return output.str();
}

std::string block_id(const std::string& function_id, const Location location) {
    return "bb_" + function_id + "_b" + format_hex(location.first) + "_" +
           format_hex(location.second);
}

bool is_header_data(const std::size_t rom_offset) noexcept {
    return rom_offset >= kHeaderDataBegin && rom_offset < kHeaderDataEnd;
}

std::optional<BankLocation> bank_for_target(const rom::Rom& image,
                                           const std::uint16_t source_bank,
                                           const std::uint16_t target) {
    if (target <= 0x3FFFU) {
        return BankLocation{0U};
    }
    if (target > 0x7FFFU || image.actual_bank_count() < 2U) {
        return std::nullopt;
    }
    if (source_bank == 0U) {
        return BankLocation{1U};
    }
    return BankLocation{source_bank};
}

std::optional<BankLocation> bank_for_fallthrough(const rom::Rom& image,
                                                 const std::uint16_t source_bank,
                                                 const std::uint32_t next_address) {
    if (next_address <= 0x3FFFU) {
        return BankLocation{0U};
    }
    if (next_address == 0x4000U && source_bank == 0U &&
        image.actual_bank_count() >= 2U) {
        return BankLocation{1U};
    }
    if (next_address <= 0x7FFFU && source_bank != 0U) {
        return BankLocation{source_bank};
    }
    return std::nullopt;
}

std::string dot_escape(const std::string_view text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (const char character : text) {
        if (character == '\\' || character == '"') {
            escaped.push_back('\\');
        }
        if (character == '\n') {
            escaped += "\\l";
        } else if (character == '\r') {
            continue;
        } else {
            escaped.push_back(character);
        }
    }
    return escaped;
}

}  // namespace

ControlFlowGraphResult build_control_flow_graphs(
    const rom::Rom& image, const std::vector<FunctionInfo>& functions,
    const std::stop_token stop_token) {
    ControlFlowGraphResult result;
    std::map<Location, std::string> function_entries;
    for (const FunctionInfo& function : functions) {
        function_entries.emplace(Location{function.bank, function.cpu_address}, function.id);
    }

    for (const FunctionInfo& function : functions) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            break;
        }

        const Location entry{function.bank, function.cpu_address};
        std::map<Location, InstructionNode> nodes;
        std::deque<Location> pending;
        std::set<Location> queued;
        pending.push_back(entry);
        queued.insert(entry);

        const auto add_edge = [&](InstructionNode& node, const CFGEdgeKind kind,
                                  const std::optional<Location> target,
                                  const bool is_call,
                                  const std::optional<ConditionOutcome> outcome) {
            TemporaryEdge edge;
            edge.kind = kind;
            edge.target = target;
            edge.condition_outcome = outcome;
            if (target.has_value()) {
                const auto other_function = function_entries.find(*target);
                if (other_function != function_entries.end() && *target != entry) {
                    edge.target_is_local = false;
                    edge.target_function_id = other_function->second;
                } else if (is_call) {
                    edge.target_is_local = false;
                    if (other_function != function_entries.end()) {
                        edge.target_function_id = other_function->second;
                    }
                } else {
                    const auto target_bank = image.bank(target->first);
                    if (target_bank.has_value()) {
                        const auto offset = target_bank->file_offset_for_cpu_address(target->second);
                        if (offset.has_value() && !is_header_data(*offset)) {
                            edge.target_is_local = true;
                            if (queued.insert(*target).second) {
                                pending.push_back(*target);
                            }
                        }
                    }
                }
            }
            node.edges.push_back(std::move(edge));
        };

        while (!pending.empty()) {
            if (stop_token.stop_requested()) {
                result.cancelled = true;
                break;
            }
            const Location current = pending.front();
            pending.pop_front();
            if (nodes.contains(current)) {
                continue;
            }
            if (current != entry && function_entries.contains(current)) {
                continue;
            }
            const auto bank = image.bank(current.first);
            if (!bank.has_value()) {
                continue;
            }
            const auto rom_offset = bank->file_offset_for_cpu_address(current.second);
            if (!rom_offset.has_value() || *rom_offset < bank->file_offset()) {
                continue;
            }
            const std::size_t local_offset = *rom_offset - bank->file_offset();
            const std::span<const std::uint8_t> bytes = bank->bytes();
            if (local_offset >= bytes.size() || is_header_data(*rom_offset)) {
                continue;
            }

            InstructionNode node;
            node.bank = current.first;
            node.address = current.second;
            node.rom_offset = *rom_offset;
            const cpu::DecodeResult decoded = cpu::decode_sm83_instruction(
                bytes.subspan(local_offset), current.second);
            if (!decoded.success()) {
                node.decode_error = decoded.error;
                nodes.emplace(current, std::move(node));
                continue;
            }
            node.instruction = *decoded.instruction;
            ++result.instructions_analyzed;
            const cpu::Instruction& instruction = *node.instruction;
            const std::uint32_t next_address =
                static_cast<std::uint32_t>(current.second) + instruction.length;
            const auto next_location = [&]() -> std::optional<Location> {
                const auto next = bank_for_fallthrough(image, current.first, next_address);
                if (!next.has_value() || next_address > 0x7FFFU) {
                    return std::nullopt;
                }
                return Location{next->bank, static_cast<std::uint16_t>(next_address)};
            };
            const auto branch_location = [&]() -> std::optional<Location> {
                if (!instruction.branch_target.has_value()) {
                    return std::nullopt;
                }
                const auto target = bank_for_target(image, current.first,
                                                    *instruction.branch_target);
                if (!target.has_value()) {
                    return std::nullopt;
                }
                return Location{target->bank, *instruction.branch_target};
            };
            const auto add_fallthrough = [&](const CFGEdgeKind kind,
                                             const std::optional<ConditionOutcome> outcome) {
                add_edge(node, kind, next_location(), false, outcome);
            };
            const auto add_branch = [&](const CFGEdgeKind kind,
                                        const std::optional<ConditionOutcome> outcome) {
                add_edge(node, kind, branch_location(), false, outcome);
            };

            switch (instruction.control_flow) {
                case cpu::ControlFlowType::Sequential:
                    add_fallthrough(CFGEdgeKind::Fallthrough, std::nullopt);
                    break;
                case cpu::ControlFlowType::ConditionalBranch:
                    add_branch(CFGEdgeKind::ConditionalTrue, ConditionOutcome::Taken);
                    add_fallthrough(CFGEdgeKind::ConditionalFalse, ConditionOutcome::NotTaken);
                    break;
                case cpu::ControlFlowType::UnconditionalBranch:
                    add_branch(CFGEdgeKind::Unconditional, std::nullopt);
                    break;
                case cpu::ControlFlowType::Call:
                case cpu::ControlFlowType::Reset: {
                    const std::optional<Location> target = branch_location();
                    add_edge(node, CFGEdgeKind::Call, target, true, std::nullopt);
                    add_fallthrough(CFGEdgeKind::Return, std::nullopt);
                    break;
                }
                case cpu::ControlFlowType::ConditionalCall: {
                    const std::optional<Location> target = branch_location();
                    add_edge(node, CFGEdgeKind::Call, target, true, ConditionOutcome::Taken);
                    add_fallthrough(CFGEdgeKind::Return, ConditionOutcome::Taken);
                    add_fallthrough(CFGEdgeKind::ConditionalFalse, ConditionOutcome::NotTaken);
                    break;
                }
                case cpu::ControlFlowType::Return:
                case cpu::ControlFlowType::InterruptReturn:
                    add_edge(node, CFGEdgeKind::Return, std::nullopt, false, std::nullopt);
                    break;
                case cpu::ControlFlowType::ConditionalReturn:
                    add_edge(node, CFGEdgeKind::Return, std::nullopt, false,
                             ConditionOutcome::Taken);
                    add_fallthrough(CFGEdgeKind::ConditionalFalse, ConditionOutcome::NotTaken);
                    break;
                case cpu::ControlFlowType::IndirectCall:
                    add_edge(node, CFGEdgeKind::Indirect, std::nullopt, false, std::nullopt);
                    add_fallthrough(CFGEdgeKind::Return, std::nullopt);
                    break;
                case cpu::ControlFlowType::IndirectJump:
                    add_edge(node, CFGEdgeKind::Indirect, std::nullopt, false, std::nullopt);
                    break;
                case cpu::ControlFlowType::Halt:
                case cpu::ControlFlowType::Stop:
                case cpu::ControlFlowType::Unknown:
                    break;
            }
            nodes.emplace(current, std::move(node));
        }
        if (result.cancelled) {
            break;
        }

        std::set<Location> leaders{entry};
        for (const auto& [location, node] : nodes) {
            if (!node.instruction.has_value()) {
                continue;
            }
            for (const TemporaryEdge& edge : node.edges) {
                if (!edge.target.has_value() || !edge.target_is_local) {
                    continue;
                }
                const bool sequential_continuation =
                    edge.kind == CFGEdgeKind::Fallthrough &&
                    node.instruction->control_flow == cpu::ControlFlowType::Sequential &&
                    edge.target->first == location.first &&
                    static_cast<std::uint32_t>(location.second) + node.instruction->length ==
                        edge.target->second;
                if (!sequential_continuation) {
                    leaders.insert(*edge.target);
                }
            }
        }

        ControlFlowGraph graph;
        graph.function_id = function.id;
        graph.function_name = function.name;
        std::map<Location, std::string> block_for_location;
        std::set<Location> assigned;
        for (const Location start : leaders) {
            if (!nodes.contains(start) || assigned.contains(start)) {
                continue;
            }
            BasicBlock block;
            block.id = block_id(function.id, start);
            block.bank = start.first;
            block.start_address = start.second;
            block.start_rom_offset = nodes.at(start).rom_offset;
            Location cursor = start;

            while (nodes.contains(cursor) && assigned.insert(cursor).second) {
                const InstructionNode& node = nodes.at(cursor);
                block_for_location.emplace(cursor, block.id);
                if (node.instruction.has_value()) {
                    block.instructions.push_back(*node.instruction);
                } else {
                    block.decode_error = node.decode_error;
                    break;
                }
                if (node.instruction->control_flow != cpu::ControlFlowType::Sequential) {
                    break;
                }
                const auto next_edge = std::find_if(node.edges.begin(), node.edges.end(),
                    [](const TemporaryEdge& edge) {
                        return edge.kind == CFGEdgeKind::Fallthrough && edge.target_is_local &&
                               edge.target.has_value();
                    });
                if (next_edge == node.edges.end() || leaders.contains(*next_edge->target) ||
                    next_edge->target->first != cursor.first ||
                    !nodes.contains(*next_edge->target)) {
                    break;
                }
                cursor = *next_edge->target;
            }
            graph.blocks.push_back(std::move(block));
        }

        const auto entry_block = block_for_location.find(entry);
        if (entry_block != block_for_location.end()) {
            graph.entry_block_id = entry_block->second;
        }
        for (const BasicBlock& block : graph.blocks) {
            if (block.decode_error.has_value() || block.instructions.empty()) {
                continue;
            }
            const cpu::Instruction& terminator = block.instructions.back();
            const Location terminal_location{block.bank, terminator.address};
            const InstructionNode& node = nodes.at(terminal_location);
            for (const TemporaryEdge& temporary : node.edges) {
                CFGEdge edge;
                edge.source_block_id = block.id;
                edge.kind = temporary.kind;
                edge.target_function_id = temporary.target_function_id;
                edge.condition_outcome = temporary.condition_outcome;
                if (temporary.target.has_value()) {
                    edge.target_bank = temporary.target->first;
                    edge.target_address = temporary.target->second;
                    if (temporary.target_is_local) {
                        const auto target_block = block_for_location.find(*temporary.target);
                        if (target_block != block_for_location.end()) {
                            edge.target_block_id = target_block->second;
                        }
                    }
                    if (!edge.target_function_id.has_value()) {
                        const auto target_function = function_entries.find(*temporary.target);
                        if (target_function != function_entries.end()) {
                            edge.target_function_id = target_function->second;
                        }
                    }
                }
                graph.edges.push_back(std::move(edge));
            }
        }
        result.graphs.push_back(std::move(graph));
    }
    return result;
}

std::string_view cfg_edge_kind_name(const CFGEdgeKind kind) noexcept {
    switch (kind) {
        case CFGEdgeKind::Fallthrough: return "fallthrough";
        case CFGEdgeKind::ConditionalTrue: return "conditional_true";
        case CFGEdgeKind::ConditionalFalse: return "conditional_false";
        case CFGEdgeKind::Unconditional: return "unconditional";
        case CFGEdgeKind::Call: return "call";
        case CFGEdgeKind::Return: return "return";
        case CFGEdgeKind::Indirect: return "indirect";
    }
    return "unknown";
}

std::string_view condition_outcome_name(const ConditionOutcome outcome) noexcept {
    switch (outcome) {
        case ConditionOutcome::Taken: return "taken";
        case ConditionOutcome::NotTaken: return "not_taken";
    }
    return "unknown";
}

std::string format_control_flow_graphs_as_dot(const ControlFlowGraphResult& result) {
    std::ostringstream output;
    output << "digraph TOOL_CFG {\n"
           << "  graph [compound=true];\n"
           << "  node [shape=box, fontname=\"Consolas\"];\n";
    std::map<std::string, std::string> function_entry_blocks;
    for (const ControlFlowGraph& graph : result.graphs) {
        function_entry_blocks.emplace(graph.function_id, graph.entry_block_id);
        output << "  subgraph cluster_" << graph.function_id << " {\n"
               << "    label=\"" << dot_escape(graph.function_name) << " ("
               << dot_escape(graph.function_id) << ")\";\n";
        for (const BasicBlock& block : graph.blocks) {
            std::ostringstream label;
            label << 'B' << format_hex(block.bank) << ":$"
                  << format_hex(block.start_address) << '\n';
            for (const cpu::Instruction& instruction : block.instructions) {
                label << '$' << format_hex(instruction.address) << "  "
                      << cpu::format_instruction(instruction) << '\n';
            }
            if (block.decode_error.has_value()) {
                label << "<decode error>\n";
            }
            output << "    " << block.id << " [label=\""
                   << dot_escape(label.str()) << "\"];\n";
        }
        output << "  }\n";
    }
    std::size_t external_node_index = 0U;
    for (const ControlFlowGraph& graph : result.graphs) {
        for (const CFGEdge& edge : graph.edges) {
            std::string target;
            if (edge.target_block_id.has_value()) {
                target = *edge.target_block_id;
            } else if (edge.target_function_id.has_value()) {
                const auto entry = function_entry_blocks.find(*edge.target_function_id);
                if (entry != function_entry_blocks.end() && !entry->second.empty()) {
                    target = entry->second;
                }
            }
            if (target.empty()) {
                target = "cfg_external_" + std::to_string(external_node_index++);
                std::string label;
                if (edge.target_function_id.has_value()) {
                    label = *edge.target_function_id;
                } else if (edge.target_bank.has_value() && edge.target_address.has_value()) {
                    label = "B" + format_hex(*edge.target_bank) + ":$" +
                            format_hex(*edge.target_address);
                } else if (edge.kind == CFGEdgeKind::Indirect) {
                    label = "indirect target";
                } else {
                    label = "return";
                }
                output << "  " << target << " [shape=oval, label=\""
                       << dot_escape(label) << "\"];\n";
            }
            output << "  " << edge.source_block_id << " -> " << target << " [label=\""
                   << cfg_edge_kind_name(edge.kind);
            if (edge.condition_outcome.has_value()) {
                output << " (" << condition_outcome_name(*edge.condition_outcome) << ')';
            }
            output << "\"];\n";
        }
    }
    output << "}\n";
    return output.str();
}

}  // namespace tool::analysis
