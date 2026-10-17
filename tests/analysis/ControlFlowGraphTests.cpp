#include "tool/analysis/ControlFlowGraph.h"
#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tool::analysis {
namespace {

std::vector<std::uint8_t> make_cfg_fixture() {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0x20U;  // JR NZ, $0158
    bytes[0x0151U] = 0x06U;
    bytes[0x0152U] = 0xCDU;  // CALL $0160
    bytes[0x0153U] = 0x60U;
    bytes[0x0154U] = 0x01U;
    bytes[0x0155U] = 0xC4U;  // CALL NZ, $0170
    bytes[0x0156U] = 0x70U;
    bytes[0x0157U] = 0x01U;
    bytes[0x0158U] = 0xC9U;
    bytes[0x0160U] = 0xC0U;  // RET NZ
    bytes[0x0161U] = 0xC9U;
    bytes[0x0170U] = 0xE9U;  // JP HL
    test::update_fixture_checksums(bytes);
    return bytes;
}

const ControlFlowGraph* find_graph(const ControlFlowGraphResult& result,
                                   const std::string& function_id) {
    const auto found = std::find_if(result.graphs.begin(), result.graphs.end(),
        [&function_id](const ControlFlowGraph& graph) {
            return graph.function_id == function_id;
        });
    return found == result.graphs.end() ? nullptr : &*found;
}

const BasicBlock* find_block(const ControlFlowGraph& graph, const std::uint16_t address) {
    const auto found = std::find_if(graph.blocks.begin(), graph.blocks.end(),
        [address](const BasicBlock& block) {
            return block.start_address == address;
        });
    return found == graph.blocks.end() ? nullptr : &*found;
}

const CFGEdge* find_edge(const ControlFlowGraph& graph, const BasicBlock& source,
                         const CFGEdgeKind kind,
                         const std::optional<ConditionOutcome> outcome = std::nullopt) {
    const auto found = std::find_if(graph.edges.begin(), graph.edges.end(),
        [&source, kind, outcome](const CFGEdge& edge) {
            return edge.source_block_id == source.id && edge.kind == kind &&
                   edge.condition_outcome == outcome;
        });
    return found == graph.edges.end() ? nullptr : &*found;
}

TEST(ControlFlowGraphTests, PreservesBranchesCallsReturnsAndIndirectFlow) {
    test::TemporaryRomFile file(make_cfg_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto image = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(image.has_value()) << load_error.message;
    const FunctionDiscoveryResult functions = discover_functions(*image);

    const ControlFlowGraphResult result = build_control_flow_graphs(*image, functions.functions);

    ASSERT_FALSE(result.cancelled);
    const ControlFlowGraph* main = find_graph(result, "fn_b0000_0100");
    ASSERT_NE(main, nullptr);
    const BasicBlock* entry = find_block(*main, 0x0100U);
    const BasicBlock* branch = find_block(*main, 0x0150U);
    const BasicBlock* call = find_block(*main, 0x0152U);
    const BasicBlock* conditional_call = find_block(*main, 0x0155U);
    const BasicBlock* returned = find_block(*main, 0x0158U);
    ASSERT_NE(entry, nullptr);
    ASSERT_NE(branch, nullptr);
    ASSERT_NE(call, nullptr);
    ASSERT_NE(conditional_call, nullptr);
    ASSERT_NE(returned, nullptr);
    ASSERT_EQ(entry->instructions.size(), 1U);
    EXPECT_EQ(entry->instructions.front().control_flow, cpu::ControlFlowType::UnconditionalBranch);
    ASSERT_EQ(branch->instructions.size(), 1U);

    const CFGEdge* jump = find_edge(*main, *entry, CFGEdgeKind::Unconditional);
    ASSERT_NE(jump, nullptr);
    ASSERT_TRUE(jump->target_block_id.has_value());
    EXPECT_EQ(*jump->target_block_id, branch->id);

    const CFGEdge* taken = find_edge(*main, *branch, CFGEdgeKind::ConditionalTrue,
                                     ConditionOutcome::Taken);
    const CFGEdge* not_taken = find_edge(*main, *branch, CFGEdgeKind::ConditionalFalse,
                                         ConditionOutcome::NotTaken);
    ASSERT_NE(taken, nullptr);
    ASSERT_NE(not_taken, nullptr);
    ASSERT_TRUE(taken->target_block_id.has_value());
    ASSERT_TRUE(not_taken->target_block_id.has_value());
    EXPECT_EQ(*taken->target_block_id, returned->id);
    EXPECT_EQ(*not_taken->target_block_id, call->id);

    const CFGEdge* call_target = find_edge(*main, *call, CFGEdgeKind::Call);
    const CFGEdge* call_return = find_edge(*main, *call, CFGEdgeKind::Return);
    ASSERT_NE(call_target, nullptr);
    ASSERT_NE(call_return, nullptr);
    EXPECT_EQ(call_target->target_function_id, std::optional<std::string>{"fn_b0000_0160"});
    ASSERT_TRUE(call_return->target_block_id.has_value());
    EXPECT_EQ(*call_return->target_block_id, conditional_call->id);

    const CFGEdge* conditional_callee = find_edge(*main, *conditional_call, CFGEdgeKind::Call,
                                                  ConditionOutcome::Taken);
    const CFGEdge* conditional_return = find_edge(*main, *conditional_call, CFGEdgeKind::Return,
                                                  ConditionOutcome::Taken);
    const CFGEdge* conditional_skip = find_edge(*main, *conditional_call,
                                                CFGEdgeKind::ConditionalFalse,
                                                ConditionOutcome::NotTaken);
    ASSERT_NE(conditional_callee, nullptr);
    ASSERT_NE(conditional_return, nullptr);
    ASSERT_NE(conditional_skip, nullptr);
    EXPECT_EQ(conditional_callee->target_function_id,
              std::optional<std::string>{"fn_b0000_0170"});
    EXPECT_EQ(conditional_return->target_block_id, std::optional<std::string>{returned->id});
    EXPECT_EQ(conditional_skip->target_block_id, std::optional<std::string>{returned->id});

    const ControlFlowGraph* conditional_ret_graph = find_graph(result, "fn_b0000_0160");
    ASSERT_NE(conditional_ret_graph, nullptr);
    const BasicBlock* conditional_ret = find_block(*conditional_ret_graph, 0x0160U);
    const BasicBlock* ret_fallthrough = find_block(*conditional_ret_graph, 0x0161U);
    ASSERT_NE(conditional_ret, nullptr);
    ASSERT_NE(ret_fallthrough, nullptr);
    ASSERT_NE(find_edge(*conditional_ret_graph, *conditional_ret, CFGEdgeKind::Return,
                        ConditionOutcome::Taken), nullptr);
    const CFGEdge* ret_not_taken = find_edge(*conditional_ret_graph, *conditional_ret,
                                             CFGEdgeKind::ConditionalFalse,
                                             ConditionOutcome::NotTaken);
    ASSERT_NE(ret_not_taken, nullptr);
    EXPECT_EQ(ret_not_taken->target_block_id,
              std::optional<std::string>{ret_fallthrough->id});

    const ControlFlowGraph* indirect_graph = find_graph(result, "fn_b0000_0170");
    ASSERT_NE(indirect_graph, nullptr);
    const BasicBlock* indirect_jump = find_block(*indirect_graph, 0x0170U);
    ASSERT_NE(indirect_jump, nullptr);
    const CFGEdge* indirect = find_edge(*indirect_graph, *indirect_jump, CFGEdgeKind::Indirect);
    ASSERT_NE(indirect, nullptr);
    EXPECT_FALSE(indirect->target_address.has_value());

    const std::string dot = format_control_flow_graphs_as_dot(result);
    EXPECT_NE(dot.find("digraph TOOL_CFG"), std::string::npos);
    EXPECT_NE(dot.find("conditional_true"), std::string::npos);
    EXPECT_NE(dot.find("conditional_false"), std::string::npos);
    EXPECT_NE(dot.find("call (taken)"), std::string::npos);
    EXPECT_NE(dot.find("indirect"), std::string::npos);
    EXPECT_NE(dot.find("return"), std::string::npos);
}

TEST(ControlFlowGraphTests, ReportsCancellation) {
    test::TemporaryRomFile file(make_cfg_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto image = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(image.has_value()) << load_error.message;
    const FunctionDiscoveryResult functions = discover_functions(*image);
    std::stop_source cancellation;
    cancellation.request_stop();

    const ControlFlowGraphResult result =
        build_control_flow_graphs(*image, functions.functions, cancellation.get_token());

    EXPECT_TRUE(result.cancelled);
}

}  // namespace
}  // namespace tool::analysis
