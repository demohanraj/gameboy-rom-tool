#include "tool/cpu/Instruction.h"

#include <iomanip>
#include <sstream>
#include <string>

namespace tool::cpu {

std::string_view instruction_category_name(const InstructionCategory category) noexcept {
    switch (category) {
        case InstructionCategory::Load: return "load";
        case InstructionCategory::Arithmetic: return "arithmetic";
        case InstructionCategory::Logical: return "logical";
        case InstructionCategory::Increment: return "increment";
        case InstructionCategory::Decrement: return "decrement";
        case InstructionCategory::Rotate: return "rotate";
        case InstructionCategory::Shift: return "shift";
        case InstructionCategory::Bit: return "bit";
        case InstructionCategory::Compare: return "compare";
        case InstructionCategory::Branch: return "branch";
        case InstructionCategory::Call: return "call";
        case InstructionCategory::Return: return "return";
        case InstructionCategory::Stack: return "stack";
        case InstructionCategory::Control: return "control";
        case InstructionCategory::Interrupt: return "interrupt";
        case InstructionCategory::Misc: return "misc";
        case InstructionCategory::Illegal: return "illegal";
    }
    return "unknown";
}

std::string_view control_flow_name(const ControlFlowType type) noexcept {
    switch (type) {
        case ControlFlowType::Sequential: return "sequential";
        case ControlFlowType::ConditionalBranch: return "conditional branch";
        case ControlFlowType::UnconditionalBranch: return "unconditional branch";
        case ControlFlowType::Call: return "call";
        case ControlFlowType::ConditionalCall: return "conditional call";
        case ControlFlowType::Return: return "return";
        case ControlFlowType::ConditionalReturn: return "conditional return";
        case ControlFlowType::Reset: return "reset";
        case ControlFlowType::IndirectJump: return "indirect jump";
        case ControlFlowType::IndirectCall: return "indirect call";
        case ControlFlowType::Halt: return "halt";
        case ControlFlowType::Stop: return "stop";
        case ControlFlowType::InterruptReturn: return "interrupt return";
        case ControlFlowType::Unknown: return "unknown";
    }
    return "unknown";
}

std::string format_flag_mask(const std::uint8_t flags) {
    std::string result;
    const auto append = [&result](const char* name) {
        if (!result.empty()) {
            result += ',';
        }
        result += name;
    };
    if ((flags & kFlagZ) != 0U) append("Z");
    if ((flags & kFlagN) != 0U) append("N");
    if ((flags & kFlagH) != 0U) append("H");
    if ((flags & kFlagC) != 0U) append("C");
    return result.empty() ? "-" : result;
}

std::string format_instruction(const Instruction& instruction) {
    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0')
           << std::setw(4) << instruction.address << ": ";
    for (std::size_t index = 0; index < 3U; ++index) {
        if (index < instruction.bytes.size()) {
            output << std::setw(2) << static_cast<unsigned>(instruction.bytes[index]) << ' ';
        } else {
            output << "   ";
        }
    }
    output << ' ' << instruction.mnemonic;
    if (!instruction.operands.empty()) {
        output << ' ' << instruction.operands;
    }
    return output.str();
}

}  // namespace tool::cpu
