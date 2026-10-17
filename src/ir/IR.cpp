#include "tool/ir/IR.h"

#include "tool/analysis/FunctionDiscovery.h"

#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <utility>

namespace tool::ir {
namespace {

std::string hex_value(const std::uint16_t value, const int digits) {
    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0') << std::setw(digits) << value;
    return output.str();
}

std::optional<std::size_t> offset_for(const rom::Rom& image,
                                      const std::uint16_t bank_index,
                                      const std::uint16_t address) {
    const auto bank = image.bank(bank_index);
    return bank.has_value() ? bank->file_offset_for_cpu_address(address) : std::nullopt;
}

IRInstruction from_cpu_instruction(const cpu::Instruction& instruction,
                                   const IRSourceLocation source) {
    IRInstruction result;
    result.kind = IROperationKind::MachineOpcode;
    result.source = source;
    result.opcode = instruction.opcode;
    result.extended_opcode = instruction.extended_opcode;
    result.encoding = instruction.bytes;
    result.category = instruction.category;
    result.control_flow = instruction.control_flow;
    result.cycles = instruction.cycles;
    result.flags_read = instruction.flags_read;
    result.flags_written = instruction.flags_written;
    result.flags_behavior_known = instruction.flags_behavior_known;
    result.reads_memory = instruction.reads_memory;
    result.writes_memory = instruction.writes_memory;
    result.memory_behavior_known = instruction.memory_behavior_known;
    result.legal = instruction.legal;
    result.mnemonic = instruction.mnemonic;
    result.operands = instruction.operands;
    return result;
}

std::string format_edges(const std::vector<analysis::CFGEdge>& edges) {
    std::ostringstream output;
    for (const analysis::CFGEdge& edge : edges) {
        output << "    edge " << edge.source_block_id << " --"
               << analysis::cfg_edge_kind_name(edge.kind);
        if (edge.condition_outcome.has_value()) {
            output << '(' << analysis::condition_outcome_name(*edge.condition_outcome) << ')';
        }
        output << "--> ";
        if (edge.target_block_id.has_value()) {
            output << *edge.target_block_id;
        } else if (edge.target_function_id.has_value()) {
            output << *edge.target_function_id;
        } else if (edge.target_bank.has_value() && edge.target_address.has_value()) {
            output << 'B' << hex_value(*edge.target_bank, 4) << ":$"
                   << hex_value(*edge.target_address, 4);
        } else {
            output << "<external/unknown>";
        }
        output << '\n';
    }
    return output.str();
}

}  // namespace

IRModule build_ir(const rom::Rom& image, const std::stop_token stop_token) {
    IRModule result;
    const analysis::FunctionDiscoveryResult discovered =
        analysis::discover_functions(image, stop_token);
    if (discovered.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }

    const analysis::ControlFlowGraphResult graphs = analysis::build_control_flow_graphs(
        image, discovered.functions, stop_token);
    if (graphs.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }

    result.functions.reserve(graphs.graphs.size());
    for (const analysis::ControlFlowGraph& graph : graphs.graphs) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            return result;
        }
        IRFunction function;
        function.id = graph.function_id;
        function.name = graph.function_name;
        function.entry_block_id = graph.entry_block_id;
        function.blocks.reserve(graph.blocks.size());
        std::map<std::string, std::vector<analysis::CFGEdge>> edges_by_source;
        for (const analysis::CFGEdge& edge : graph.edges) {
            edges_by_source[edge.source_block_id].push_back(edge);
        }

        for (const analysis::BasicBlock& block : graph.blocks) {
            if (stop_token.stop_requested()) {
                result.cancelled = true;
                return result;
            }
            IRBasicBlock ir_block;
            ir_block.id = block.id;
            ir_block.bank = block.bank;
            ir_block.start_address = block.start_address;
            ir_block.start_rom_offset = block.start_rom_offset;
            ir_block.instructions.reserve(block.instructions.size() +
                (block.instructions.empty() && block.decode_error.has_value() ? 1U : 0U));

            if (block.instructions.empty() && block.decode_error.has_value()) {
                IRInstruction failure;
                failure.kind = IROperationKind::DecodeFailure;
                failure.source = {block.bank, block.start_address, block.start_rom_offset};
                failure.decode_error = block.decode_error;
                failure.control_flow = cpu::ControlFlowType::Unknown;
                ir_block.instructions.push_back(std::move(failure));
                ++result.decode_failure_count;
            }

            for (const cpu::Instruction& instruction : block.instructions) {
                const auto rom_offset = offset_for(image, block.bank, instruction.address);
                const IRSourceLocation source{block.bank, instruction.address,
                    rom_offset.value_or(block.start_rom_offset)};
                ir_block.instructions.push_back(from_cpu_instruction(instruction, source));
                ++result.instruction_count;
            }
            const auto block_edges = edges_by_source.find(block.id);
            if (block_edges != edges_by_source.end()) {
                ir_block.successors = block_edges->second;
            }
            result.edge_count += ir_block.successors.size();
            ++result.basic_block_count;
            function.blocks.push_back(std::move(ir_block));
        }
        result.functions.push_back(std::move(function));
    }
    return result;
}

std::string_view ir_operation_kind_name(const IROperationKind kind) noexcept {
    switch (kind) {
        case IROperationKind::MachineOpcode: return "machine-opcode";
        case IROperationKind::DecodeFailure: return "decode-failure";
    }
    return "unknown";
}

std::string format_ir_instruction(const IRInstruction& instruction) {
    std::ostringstream output;
    output << "B" << hex_value(instruction.source.bank, 4) << ":$"
           << hex_value(instruction.source.cpu_address, 4) << " @ROM$"
           << std::uppercase << std::hex << std::setfill('0') << std::setw(6)
           << instruction.source.rom_offset << "  ";
    if (instruction.kind == IROperationKind::DecodeFailure) {
        output << "decode-failure";
        if (instruction.decode_error.has_value()) {
            output << " code=" << static_cast<unsigned>(*instruction.decode_error);
        }
        return output.str();
    }

    output << "machine-opcode=";
    if (instruction.extended_opcode.has_value()) {
        output << "CB:" << std::setw(2)
               << static_cast<unsigned>(*instruction.extended_opcode);
    } else {
        output << "BASE:" << std::setw(2) << static_cast<unsigned>(instruction.opcode);
    }
    output << " bytes=";
    for (const std::uint8_t byte : instruction.encoding) {
        output << std::setw(2) << static_cast<unsigned>(byte) << ' ';
    }
    output << " op=" << cpu::instruction_category_name(instruction.category)
           << " flow=" << cpu::control_flow_name(instruction.control_flow)
           << " flags=" << (instruction.flags_behavior_known ? "known" : "unknown")
           << "(r:" << cpu::format_flag_mask(instruction.flags_read)
           << ",w:" << cpu::format_flag_mask(instruction.flags_written) << ')'
           << " memory=";
    if (!instruction.memory_behavior_known) {
        output << "unknown";
    } else if (instruction.reads_memory && instruction.writes_memory) {
        output << "read/write";
    } else if (instruction.reads_memory) {
        output << "read";
    } else if (instruction.writes_memory) {
        output << "write";
    } else {
        output << "none";
    }
    output << " cycles=" << std::dec << static_cast<unsigned>(instruction.cycles.taken);
    if (instruction.cycles.conditional) {
        output << '/' << static_cast<unsigned>(instruction.cycles.not_taken);
    }
    output << " | " << instruction.mnemonic;
    if (!instruction.operands.empty()) {
        output << ' ' << instruction.operands;
    }
    if (!instruction.legal) {
        output << " [illegal/undocumented]";
    }
    return output.str();
}

std::string format_ir_module(const IRModule& module) {
    std::ostringstream output;
    output << "TOOL opcode-level IR; machine-opcode IR (CPU semantic lifting is Phase 10)\n"
           << "Functions: " << module.functions.size()
           << "; blocks: " << module.basic_block_count
           << "; instructions: " << module.instruction_count
           << "; edges: " << module.edge_count
           << "; decode failures: " << module.decode_failure_count << '\n';
    for (const IRFunction& function : module.functions) {
        output << "\nfunction " << function.name << " id=" << function.id
               << " entry=" << function.entry_block_id << '\n';
        for (const IRBasicBlock& block : function.blocks) {
            output << "  block " << block.id << " B" << hex_value(block.bank, 4)
                   << ":$" << hex_value(block.start_address, 4)
                   << " instructions=" << block.instructions.size() << '\n';
            for (const IRInstruction& instruction : block.instructions) {
                output << "    " << format_ir_instruction(instruction) << '\n';
            }
            output << format_edges(block.successors);
        }
    }
    if (module.cancelled) {
        output << "\nIR build cancelled.\n";
    }
    return output.str();
}

}  // namespace tool::ir
