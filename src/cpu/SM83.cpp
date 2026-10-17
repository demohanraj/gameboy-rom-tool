#include "tool/cpu/SM83.h"

#include "tool/cpu/OpcodeTable.h"

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace tool::cpu {
namespace {

std::string hex_value(const std::uint16_t value, const int digits) {
    std::ostringstream output;
    output << '$' << std::uppercase << std::hex << std::setfill('0')
           << std::setw(digits) << value;
    return output.str();
}

std::uint16_t read_u16_le(const std::span<const std::uint8_t> bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[1]) |
        (static_cast<std::uint16_t>(bytes[2]) << 8U));
}

std::int16_t signed_byte(const std::uint8_t value) noexcept {
    if (value < 0x80U) {
        return static_cast<std::int16_t>(value);
    }
    return static_cast<std::int16_t>(static_cast<std::int16_t>(value) - 0x100);
}

void replace_all(std::string& text, const std::string_view needle,
                 const std::string& replacement) {
    std::size_t position = 0;
    while ((position = text.find(needle, position)) != std::string::npos) {
        text.replace(position, needle.size(), replacement);
        position += replacement.size();
    }
}

}  // namespace

DecodeResult decode_sm83_instruction(const std::span<const std::uint8_t> bytes,
                                     const std::uint16_t address) {
    if (bytes.empty()) {
        return {std::nullopt, DecodeErrorCode::NoOpcode, 1U, 0U};
    }

    const std::uint8_t opcode = bytes[0];
    const bool cb_prefixed = opcode == 0xCBU;
    if (cb_prefixed && bytes.size() < 2U) {
        return {std::nullopt, DecodeErrorCode::MissingCbOpcode, 2U, bytes.size()};
    }

    const OpcodeMetadata& metadata = cb_prefixed
        ? cb_opcode_metadata(bytes[1])
        : base_opcode_metadata(opcode);
    if (bytes.size() < metadata.length) {
        return {std::nullopt, DecodeErrorCode::TruncatedInstruction,
                metadata.length, bytes.size()};
    }

    Instruction instruction;
    instruction.address = address;
    instruction.opcode = opcode;
    if (cb_prefixed) {
        instruction.extended_opcode = bytes[1];
    }
    instruction.bytes.assign(bytes.begin(),
                             bytes.begin() + static_cast<std::ptrdiff_t>(metadata.length));
    instruction.mnemonic = metadata.mnemonic;
    instruction.operands = metadata.operands;
    instruction.length = metadata.length;
    instruction.cycles = metadata.cycles;
    instruction.flags_read = metadata.flags_read;
    instruction.flags_written = metadata.flags_written;
    instruction.flags_behavior_known = metadata.flags_behavior_known;
    instruction.reads_memory = metadata.reads_memory;
    instruction.writes_memory = metadata.writes_memory;
    instruction.memory_behavior_known = metadata.memory_behavior_known;
    instruction.category = metadata.category;
    instruction.control_flow = metadata.control_flow;
    instruction.branch_target = metadata.fixed_branch_target;
    instruction.legal = metadata.legal;

    const bool relative_branch = metadata.operands.find("e8") != std::string::npos &&
        (metadata.control_flow == ControlFlowType::ConditionalBranch ||
         metadata.control_flow == ControlFlowType::UnconditionalBranch);
    if (relative_branch) {
        const std::int16_t displacement = signed_byte(bytes[1]);
        const std::int32_t target = static_cast<std::int32_t>(address) +
            static_cast<std::int32_t>(metadata.length) + displacement;
        const auto wrapped_target = static_cast<std::uint16_t>(
            static_cast<std::uint32_t>(target) & 0xFFFFU);
        instruction.branch_target = wrapped_target;
        replace_all(instruction.operands, "e8", hex_value(wrapped_target, 4));
    } else if (instruction.operands.find("e8") != std::string::npos) {
        const std::int16_t displacement = signed_byte(bytes[1]);
        std::string signed_value;
        if (displacement < 0) {
            const auto magnitude = static_cast<std::uint16_t>(-displacement);
            signed_value = "-" + hex_value(magnitude, 2);
        } else {
            signed_value = "+" + hex_value(static_cast<std::uint16_t>(displacement), 2);
        }
        replace_all(instruction.operands, "e8", signed_value);
    }

    if (instruction.operands.find("a16") != std::string::npos) {
        const std::uint16_t immediate = read_u16_le(bytes);
        replace_all(instruction.operands, "a16", hex_value(immediate, 4));
        if (metadata.control_flow == ControlFlowType::ConditionalBranch ||
            metadata.control_flow == ControlFlowType::UnconditionalBranch ||
            metadata.control_flow == ControlFlowType::ConditionalCall ||
            metadata.control_flow == ControlFlowType::Call) {
            instruction.branch_target = immediate;
        }
    }
    if (instruction.operands.find("d16") != std::string::npos) {
        replace_all(instruction.operands, "d16", hex_value(read_u16_le(bytes), 4));
    }
    if (instruction.operands.find("d8") != std::string::npos) {
        replace_all(instruction.operands, "d8", hex_value(bytes[1], 2));
    }
    if (instruction.operands.find("a8") != std::string::npos) {
        replace_all(instruction.operands, "a8", "$FF00+" + hex_value(bytes[1], 2));
    }

    return {std::move(instruction), DecodeErrorCode::None,
            metadata.length, bytes.size()};
}

}  // namespace tool::cpu
