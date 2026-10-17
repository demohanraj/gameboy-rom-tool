#include "tool/ir/IR.h"

#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <stop_token>
#include <vector>

namespace tool::ir {
namespace {

std::vector<std::uint8_t> make_ir_fixture() {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0x3EU;  // LD A, $2A
    bytes[0x0151U] = 0x2AU;
    bytes[0x0152U] = 0xEAU;  // LD [$C000], A
    bytes[0x0153U] = 0x00U;
    bytes[0x0154U] = 0xC0U;
    bytes[0x0155U] = 0x20U;  // JR NZ, $0158
    bytes[0x0156U] = 0x01U;
    bytes[0x0157U] = 0xC9U;
    bytes[0x0158U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    return bytes;
}

TEST(IRTests, PreservesInstructionEncodingEffectsAndControlFlowStructure) {
    test::TemporaryRomFile file(make_ir_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    const IRModule module = build_ir(*loaded);

    ASSERT_FALSE(module.cancelled);
    EXPECT_GT(module.instruction_count, 0U);
    EXPECT_GT(module.basic_block_count, 0U);
    EXPECT_GT(module.edge_count, 0U);
    const auto function = std::find_if(module.functions.begin(), module.functions.end(),
        [](const IRFunction& item) { return item.id == "fn_b0000_0100"; });
    ASSERT_NE(function, module.functions.end());
    const auto block = std::find_if(function->blocks.begin(), function->blocks.end(),
        [](const IRBasicBlock& item) { return item.start_address == 0x0150U; });
    ASSERT_NE(block, function->blocks.end());
    ASSERT_GE(block->instructions.size(), 3U);

    const IRInstruction& load = block->instructions[0];
    EXPECT_EQ(load.kind, IROperationKind::MachineOpcode);
    EXPECT_EQ(load.opcode, 0x3EU);
    EXPECT_EQ(load.encoding, (std::vector<std::uint8_t>{0x3EU, 0x2AU}));
    EXPECT_EQ(load.source.bank, 0U);
    EXPECT_EQ(load.source.cpu_address, 0x0150U);
    EXPECT_EQ(load.source.rom_offset, 0x0150U);
    EXPECT_EQ(load.category, cpu::InstructionCategory::Load);
    EXPECT_EQ(load.cycles.taken, 8U);

    const IRInstruction& store = block->instructions[1];
    EXPECT_TRUE(store.writes_memory);
    EXPECT_TRUE(store.memory_behavior_known);
    EXPECT_EQ(store.source.cpu_address, 0x0152U);

    const IRInstruction& branch = block->instructions[2];
    EXPECT_EQ(branch.control_flow, cpu::ControlFlowType::ConditionalBranch);
    EXPECT_TRUE(branch.cycles.conditional);
    EXPECT_NE(std::find_if(block->successors.begin(), block->successors.end(),
        [](const analysis::CFGEdge& edge) {
            return edge.kind == analysis::CFGEdgeKind::ConditionalTrue;
        }), block->successors.end());
    EXPECT_NE(std::find_if(block->successors.begin(), block->successors.end(),
        [](const analysis::CFGEdge& edge) {
            return edge.kind == analysis::CFGEdgeKind::ConditionalFalse;
        }), block->successors.end());

    const std::string formatted = format_ir_module(module);
    EXPECT_NE(formatted.find("machine-opcode IR (CPU semantic lifting is Phase 10)"),
              std::string::npos);
    EXPECT_NE(formatted.find("machine-opcode=BASE:3E"), std::string::npos);
    EXPECT_NE(formatted.find("flags=known"), std::string::npos);
    EXPECT_NE(formatted.find("conditional_true"), std::string::npos);
}

TEST(IRTests, HonorsPreRequestedCancellation) {
    test::TemporaryRomFile file(make_ir_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;
    std::stop_source source;
    source.request_stop();

    const IRModule module = build_ir(*loaded, source.get_token());

    EXPECT_TRUE(module.cancelled);
    EXPECT_TRUE(module.functions.empty());
}

TEST(IRTests, KeepsTruncatedDecodeAsAnExplicitIrNode) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $7FFF in the switchable bank.
    bytes[0x0101U] = 0xFFU;
    bytes[0x0102U] = 0x7FU;
    bytes[0x7FFFU] = 0xC3U;  // JP is truncated at the physical ROM end.
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    const IRModule module = build_ir(*loaded);

    ASSERT_FALSE(module.cancelled);
    ASSERT_EQ(module.decode_failure_count, 1U);
    const auto function = std::find_if(module.functions.begin(), module.functions.end(),
        [](const IRFunction& item) { return item.id == "fn_b0000_0100"; });
    ASSERT_NE(function, module.functions.end());
    const auto failure_block = std::find_if(function->blocks.begin(), function->blocks.end(),
        [](const IRBasicBlock& block) {
            return block.start_address == 0x7FFFU && block.bank == 1U;
        });
    ASSERT_NE(failure_block, function->blocks.end());
    ASSERT_EQ(failure_block->instructions.size(), 1U);
    EXPECT_EQ(failure_block->instructions.front().kind, IROperationKind::DecodeFailure);
    EXPECT_TRUE(failure_block->instructions.front().decode_error.has_value());
}

}  // namespace
}  // namespace tool::ir
