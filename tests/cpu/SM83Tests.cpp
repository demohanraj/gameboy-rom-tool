#include "tool/cpu/OpcodeTable.h"
#include "tool/cpu/SM83.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace tool::cpu {
namespace {

TEST(SM83Tests, DecodesEveryBaseAndCbOpcodeFromCentralTables) {
    std::size_t legal_base_count = 0;
    for (std::size_t value = 0; value < 256U; ++value) {
        const auto opcode = static_cast<std::uint8_t>(value);
        const std::array<std::uint8_t, 3> bytes{opcode, 0x34U, 0x12U};
        const DecodeResult result = decode_sm83_instruction(bytes, 0x0100U);
        ASSERT_TRUE(result.success()) << "base opcode 0x" << std::hex << value;
        const OpcodeMetadata& metadata = opcode == 0xCBU
            ? cb_opcode_metadata(bytes[1])
            : base_opcode_metadata(opcode);
        EXPECT_EQ(result.instruction->length, metadata.length);
        EXPECT_EQ(result.instruction->legal, metadata.legal);
        EXPECT_EQ(result.instruction->category, metadata.category);
        EXPECT_EQ(result.instruction->cycles.taken, metadata.cycles.taken);
        EXPECT_EQ(result.instruction->control_flow, metadata.control_flow);
        if (metadata.legal) {
            ++legal_base_count;
        }
        if (opcode != 0xCBU && metadata.length > 1U) {
            const auto partial = std::span<const std::uint8_t>(bytes.data(), metadata.length - 1U);
            EXPECT_FALSE(decode_sm83_instruction(partial, 0x0100U).success())
                << "truncated base opcode 0x" << std::hex << value;
        }

        const auto cb_opcode = static_cast<std::uint8_t>(value);
        const std::array<std::uint8_t, 3> cb_bytes{0xCBU, cb_opcode, 0x00U};
        const DecodeResult cb_result = decode_sm83_instruction(cb_bytes, 0x0100U);
        ASSERT_TRUE(cb_result.success()) << "CB opcode 0x" << std::hex << value;
        EXPECT_EQ(cb_result.instruction->extended_opcode, cb_opcode);
        EXPECT_EQ(cb_result.instruction->length, cb_opcode_metadata(cb_opcode).length);
        EXPECT_TRUE(cb_result.instruction->legal);
        EXPECT_EQ(cb_result.instruction->category, cb_opcode_metadata(cb_opcode).category);
    }
    EXPECT_EQ(legal_base_count, 245U);
    const std::array<std::uint8_t, 1> short_cb{0xCBU};
    EXPECT_FALSE(decode_sm83_instruction(short_cb, 0x0100U).success());
}

TEST(SM83Tests, MarksOnlyTheUndocumentedBaseOpcodesIllegal) {
    constexpr std::array<std::uint8_t, 11> illegal{
        0xD3U, 0xDBU, 0xDDU, 0xE3U, 0xE4U, 0xEBU,
        0xECU, 0xEDU, 0xF4U, 0xFCU, 0xFDU,
    };
    for (const std::uint8_t opcode : illegal) {
        EXPECT_FALSE(base_opcode_metadata(opcode).legal);
    }
}

TEST(SM83Tests, ReportsNoOpcodeMissingPrefixByteAndTruncatedOperands) {
    const DecodeResult empty = decode_sm83_instruction({}, 0x0100U);
    EXPECT_EQ(empty.error, DecodeErrorCode::NoOpcode);
    EXPECT_EQ(empty.required_bytes, 1U);

    const std::array<std::uint8_t, 1> prefix{0xCBU};
    const DecodeResult missing_cb = decode_sm83_instruction(prefix, 0x0100U);
    EXPECT_EQ(missing_cb.error, DecodeErrorCode::MissingCbOpcode);
    EXPECT_EQ(missing_cb.required_bytes, 2U);

    const std::array<std::uint8_t, 2> truncated_word{0xC3U, 0x34U};
    const DecodeResult truncated = decode_sm83_instruction(truncated_word, 0x0100U);
    EXPECT_EQ(truncated.error, DecodeErrorCode::TruncatedInstruction);
    EXPECT_EQ(truncated.required_bytes, 3U);
    EXPECT_EQ(truncated.available_bytes, 2U);
}

TEST(SM83Tests, ResolvesRelativeAndAbsoluteControlFlowTargets) {
    const std::array<std::uint8_t, 2> relative{0x18U, 0xFEU};
    const DecodeResult relative_result = decode_sm83_instruction(relative, 0x0100U);
    ASSERT_TRUE(relative_result.success());
    EXPECT_EQ(relative_result.instruction->branch_target, 0x0100U);
    EXPECT_EQ(relative_result.instruction->operands, "$0100");

    const std::array<std::uint8_t, 3> conditional{0xC2U, 0x34U, 0x12U};
    const DecodeResult conditional_result = decode_sm83_instruction(conditional, 0x0200U);
    ASSERT_TRUE(conditional_result.success());
    EXPECT_EQ(conditional_result.instruction->branch_target, 0x1234U);
    EXPECT_EQ(conditional_result.instruction->control_flow, ControlFlowType::ConditionalBranch);
    EXPECT_EQ(conditional_result.instruction->flags_read, kFlagZ);
    EXPECT_EQ(conditional_result.instruction->cycles.taken, 16U);
    EXPECT_EQ(conditional_result.instruction->cycles.not_taken, 12U);
}

TEST(SM83Tests, DescribesCallStackMemoryAndImmediateFormatting) {
    const std::array<std::uint8_t, 3> call{0xCDU, 0x78U, 0x56U};
    const DecodeResult call_result = decode_sm83_instruction(call, 0x0150U);
    ASSERT_TRUE(call_result.success());
    EXPECT_EQ(call_result.instruction->branch_target, 0x5678U);
    EXPECT_TRUE(call_result.instruction->writes_memory);
    EXPECT_FALSE(call_result.instruction->reads_memory);
    EXPECT_EQ(call_result.instruction->control_flow, ControlFlowType::Call);

    const std::array<std::uint8_t, 2> load{0x3EU, 0x42U};
    const DecodeResult load_result = decode_sm83_instruction(load, 0x0100U);
    ASSERT_TRUE(load_result.success());
    EXPECT_EQ(load_result.instruction->operands, "A, $42");
    EXPECT_NE(format_instruction(*load_result.instruction).find("LD A, $42"), std::string::npos);
}

TEST(SM83Tests, DescribesCbMemoryAndFlagEffects) {
    const std::array<std::uint8_t, 2> bit_hl{0xCBU, 0x7EU};
    const DecodeResult bit_result = decode_sm83_instruction(bit_hl, 0x0200U);
    ASSERT_TRUE(bit_result.success());
    EXPECT_EQ(bit_result.instruction->mnemonic, "BIT");
    EXPECT_TRUE(bit_result.instruction->reads_memory);
    EXPECT_FALSE(bit_result.instruction->writes_memory);
    EXPECT_EQ(bit_result.instruction->flags_written,
              static_cast<std::uint8_t>(kFlagZ | kFlagN | kFlagH));
    EXPECT_EQ(bit_result.instruction->cycles.taken, 12U);

    const std::array<std::uint8_t, 2> set_hl{0xCBU, 0xC6U};
    const DecodeResult set_result = decode_sm83_instruction(set_hl, 0x0200U);
    ASSERT_TRUE(set_result.success());
    EXPECT_EQ(set_result.instruction->mnemonic, "SET");
    EXPECT_TRUE(set_result.instruction->reads_memory);
    EXPECT_TRUE(set_result.instruction->writes_memory);
    EXPECT_EQ(set_result.instruction->flags_written, 0U);
    EXPECT_EQ(set_result.instruction->cycles.taken, 16U);
}

TEST(SM83Tests, DecodesHighMemoryAndSignedStackOffsets) {
    const std::array<std::uint8_t, 2> load_high{0xE0U, 0x80U};
    const DecodeResult high_result = decode_sm83_instruction(load_high, 0x0100U);
    ASSERT_TRUE(high_result.success());
    EXPECT_EQ(high_result.instruction->operands, "[$FF00+$80], A");
    EXPECT_TRUE(high_result.instruction->writes_memory);

    const std::array<std::uint8_t, 2> add_sp{0xE8U, 0xFEU};
    const DecodeResult add_result = decode_sm83_instruction(add_sp, 0x0100U);
    ASSERT_TRUE(add_result.success());
    EXPECT_EQ(add_result.instruction->operands, "SP, -$02");
    EXPECT_EQ(add_result.instruction->flags_written, kAllFlags);
}

TEST(SM83Tests, UsesCorrectIndirectJumpOperandAndSwapCategory) {
    const std::array<std::uint8_t, 1> jump_hl{0xE9U};
    const DecodeResult jump_result = decode_sm83_instruction(jump_hl, 0x0100U);
    ASSERT_TRUE(jump_result.success());
    EXPECT_EQ(jump_result.instruction->operands, "HL");
    EXPECT_EQ(jump_result.instruction->control_flow, ControlFlowType::IndirectJump);

    const std::array<std::uint8_t, 2> swap_a{0xCBU, 0x37U};
    const DecodeResult swap_result = decode_sm83_instruction(swap_a, 0x0100U);
    ASSERT_TRUE(swap_result.success());
    EXPECT_EQ(swap_result.instruction->mnemonic, "SWAP");
    EXPECT_EQ(swap_result.instruction->category, InstructionCategory::Misc);
}

TEST(SM83Tests, DecodesStopAndPreservesItsIgnoredSecondByte) {
    const std::array<std::uint8_t, 2> stop{0x10U, 0xA5U};
    const DecodeResult result = decode_sm83_instruction(stop, 0x0100U);
    ASSERT_TRUE(result.success());
    EXPECT_EQ(result.instruction->length, 2U);
    ASSERT_EQ(result.instruction->bytes.size(), 2U);
    EXPECT_EQ(result.instruction->bytes[1], 0xA5U);
    EXPECT_EQ(result.instruction->control_flow, ControlFlowType::Stop);
}

TEST(SM83Tests, RepresentsUndocumentedOpcodeAsUnknownRatherThanCrashing) {
    const std::array<std::uint8_t, 1> illegal{0xD3U};
    const DecodeResult result = decode_sm83_instruction(illegal, 0x0100U);
    ASSERT_TRUE(result.success());
    EXPECT_FALSE(result.instruction->legal);
    EXPECT_EQ(result.instruction->category, InstructionCategory::Illegal);
    EXPECT_EQ(result.instruction->control_flow, ControlFlowType::Unknown);
    EXPECT_FALSE(result.instruction->flags_behavior_known);
    EXPECT_FALSE(result.instruction->memory_behavior_known);
}

}  // namespace
}  // namespace tool::cpu
