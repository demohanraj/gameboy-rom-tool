#include "tool/cpu/OpcodeTable.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tool::cpu {
namespace {

using Category = InstructionCategory;
using Flow = ControlFlowType;

constexpr std::array<std::string_view, 8> kRegisters8{
    "B", "C", "D", "E", "H", "L", "[HL]", "A",
};
constexpr std::array<std::string_view, 4> kRegisters16{
    "BC", "DE", "HL", "SP",
};
constexpr std::array<std::string_view, 4> kConditions{
    "NZ", "Z", "NC", "C",
};
constexpr std::array<std::string_view, 8> kAluMnemonics{
    "ADD", "ADC", "SUB", "SBC", "AND", "XOR", "OR", "CP",
};
constexpr std::array<std::string_view, 8> kCbMnemonics{
    "RLC", "RRC", "RL", "RR", "SLA", "SRA", "SWAP", "SRL",
};

void initialize_illegal_table(OpcodeTable& table, const bool cb_prefixed) {
    for (std::size_t index = 0; index < table.size(); ++index) {
        OpcodeMetadata& metadata = table[index];
        metadata.opcode = static_cast<std::uint8_t>(index);
        metadata.cb_prefixed = cb_prefixed;
        metadata.length = cb_prefixed ? 2U : 1U;
        metadata.mnemonic = "ILLEGAL";
        metadata.category = Category::Illegal;
        metadata.flags_behavior_known = false;
        metadata.memory_behavior_known = false;
        metadata.control_flow = Flow::Unknown;
    }
}

void set(OpcodeTable& table, const std::uint8_t opcode, const bool cb_prefixed,
         std::string mnemonic, std::string operands, const std::uint8_t length,
         const std::uint8_t cycles_taken, const std::uint8_t cycles_not_taken,
         const Category category, const std::uint8_t flags_read = 0U,
         const std::uint8_t flags_written = 0U, const Flow flow = Flow::Sequential,
         const bool reads_memory = false, const bool writes_memory = false,
         const bool flags_known = true, const bool memory_known = true,
         const std::optional<std::uint16_t> fixed_target = std::nullopt) {
    OpcodeMetadata& metadata = table[opcode];
    metadata.opcode = opcode;
    metadata.cb_prefixed = cb_prefixed;
    metadata.length = length;
    metadata.cycles = {cycles_taken, cycles_not_taken,
                       cycles_taken != cycles_not_taken};
    metadata.mnemonic = std::move(mnemonic);
    metadata.operands = std::move(operands);
    metadata.category = category;
    metadata.flags_read = flags_read;
    metadata.flags_written = flags_written;
    metadata.flags_behavior_known = flags_known;
    metadata.reads_memory = reads_memory;
    metadata.writes_memory = writes_memory;
    metadata.memory_behavior_known = memory_known;
    metadata.control_flow = flow;
    metadata.fixed_branch_target = fixed_target;
    metadata.legal = true;
}

OpcodeTable make_base_table() {
    OpcodeTable table{};
    initialize_illegal_table(table, false);

    set(table, 0x00U, false, "NOP", "", 1U, 4U, 4U, Category::Misc);

    for (std::size_t pair = 0; pair < kRegisters16.size(); ++pair) {
        const auto pair_offset = static_cast<std::uint8_t>(pair * 0x10U);
        const auto load_imm = static_cast<std::uint8_t>(0x01U + pair_offset);
        const auto increment = static_cast<std::uint8_t>(0x03U + pair_offset);
        const auto add_hl = static_cast<std::uint8_t>(0x09U + pair_offset);
        const auto decrement = static_cast<std::uint8_t>(0x0BU + pair_offset);
        const std::string pair_name(kRegisters16[pair]);
        set(table, load_imm, false, "LD", pair_name + ", d16", 3U, 12U, 12U,
            Category::Load);
        set(table, increment, false, "INC", pair_name, 1U, 8U, 8U,
            Category::Increment);
        set(table, add_hl, false, "ADD", "HL, " + pair_name, 1U, 8U, 8U,
            Category::Arithmetic, 0U, static_cast<std::uint8_t>(kFlagN | kFlagH | kFlagC));
        set(table, decrement, false, "DEC", pair_name, 1U, 8U, 8U,
            Category::Decrement);
    }

    const std::array<std::string_view, 4> indirect_pairs{"[BC]", "[DE]", "[HL+]", "[HL-]"};
    for (std::size_t pair = 0; pair < indirect_pairs.size(); ++pair) {
        const auto pair_offset = static_cast<std::uint8_t>(pair * 0x10U);
        const auto store = static_cast<std::uint8_t>(0x02U + pair_offset);
        const auto load = static_cast<std::uint8_t>(0x0AU + pair_offset);
        constexpr std::uint8_t store_cycles = 8U;
        constexpr std::uint8_t load_cycles = 8U;
        set(table, store, false, "LD", std::string(indirect_pairs[pair]) + ", A", 1U,
            store_cycles, store_cycles, Category::Load, 0U, 0U, Flow::Sequential,
            false, true);
        set(table, load, false, "LD", "A, " + std::string(indirect_pairs[pair]), 1U,
            load_cycles, load_cycles, Category::Load, 0U, 0U, Flow::Sequential,
            true, false);
    }

    set(table, 0x08U, false, "LD", "[a16], SP", 3U, 20U, 20U,
        Category::Load, 0U, 0U, Flow::Sequential, false, true);

    for (std::size_t reg = 0; reg < kRegisters8.size(); ++reg) {
        const auto reg_offset = static_cast<std::uint8_t>(reg * 8U);
        const std::string reg_name(kRegisters8[reg]);
        const bool indirect = reg == 6U;
        const std::uint8_t memory_cycles = indirect ? 12U : 4U;
        set(table, static_cast<std::uint8_t>(0x04U + reg_offset), false, "INC",
            reg_name, 1U, memory_cycles, memory_cycles, Category::Increment,
            0U, static_cast<std::uint8_t>(kFlagZ | kFlagN | kFlagH), Flow::Sequential,
            indirect, indirect);
        set(table, static_cast<std::uint8_t>(0x05U + reg_offset), false, "DEC",
            reg_name, 1U, memory_cycles, memory_cycles, Category::Decrement,
            0U, static_cast<std::uint8_t>(kFlagZ | kFlagN | kFlagH), Flow::Sequential,
            indirect, indirect);
        const std::uint8_t immediate_cycles = indirect ? 12U : 8U;
        set(table, static_cast<std::uint8_t>(0x06U + reg_offset), false, "LD",
            reg_name + ", d8", 2U, immediate_cycles, immediate_cycles, Category::Load,
            0U, 0U, Flow::Sequential, false, indirect);
    }

    set(table, 0x07U, false, "RLCA", "", 1U, 4U, 4U, Category::Rotate,
        0U, kAllFlags);
    set(table, 0x0FU, false, "RRCA", "", 1U, 4U, 4U, Category::Rotate,
        0U, kAllFlags);
    set(table, 0x17U, false, "RLA", "", 1U, 4U, 4U, Category::Rotate,
        kFlagC, kAllFlags);
    set(table, 0x1FU, false, "RRA", "", 1U, 4U, 4U, Category::Rotate,
        kFlagC, kAllFlags);
    set(table, 0x10U, false, "STOP", "", 2U, 4U, 4U, Category::Control,
        0U, 0U, Flow::Stop);
    set(table, 0x18U, false, "JR", "e8", 2U, 12U, 12U, Category::Branch,
        0U, 0U, Flow::UnconditionalBranch);
    set(table, 0x20U, false, "JR", "NZ, e8", 2U, 12U, 8U, Category::Branch,
        kFlagZ, 0U, Flow::ConditionalBranch);
    set(table, 0x28U, false, "JR", "Z, e8", 2U, 12U, 8U, Category::Branch,
        kFlagZ, 0U, Flow::ConditionalBranch);
    set(table, 0x30U, false, "JR", "NC, e8", 2U, 12U, 8U, Category::Branch,
        kFlagC, 0U, Flow::ConditionalBranch);
    set(table, 0x38U, false, "JR", "C, e8", 2U, 12U, 8U, Category::Branch,
        kFlagC, 0U, Flow::ConditionalBranch);
    set(table, 0x27U, false, "DAA", "", 1U, 4U, 4U, Category::Arithmetic,
        static_cast<std::uint8_t>(kFlagN | kFlagH | kFlagC),
        static_cast<std::uint8_t>(kFlagZ | kFlagH | kFlagC));
    set(table, 0x2FU, false, "CPL", "", 1U, 4U, 4U, Category::Logical,
        0U, static_cast<std::uint8_t>(kFlagN | kFlagH));
    set(table, 0x37U, false, "SCF", "", 1U, 4U, 4U, Category::Control,
        0U, static_cast<std::uint8_t>(kFlagN | kFlagH | kFlagC));
    set(table, 0x3FU, false, "CCF", "", 1U, 4U, 4U, Category::Control,
        kFlagC, static_cast<std::uint8_t>(kFlagN | kFlagH | kFlagC));

    for (std::size_t destination = 0; destination < kRegisters8.size(); ++destination) {
        for (std::size_t source = 0; source < kRegisters8.size(); ++source) {
            const auto opcode = static_cast<std::uint8_t>(0x40U + destination * 8U + source);
            if (opcode == 0x76U) {
                set(table, opcode, false, "HALT", "", 1U, 4U, 4U,
                    Category::Control, 0U, 0U, Flow::Halt);
                continue;
            }
            const bool reads_memory = source == 6U;
            const bool writes_memory = destination == 6U;
            const std::uint8_t cycles = (reads_memory || writes_memory) ? 8U : 4U;
            set(table, opcode, false, "LD",
                std::string(kRegisters8[destination]) + ", " + std::string(kRegisters8[source]),
                1U, cycles, cycles, Category::Load, 0U, 0U, Flow::Sequential,
                reads_memory, writes_memory);
        }
    }

    for (std::size_t operation = 0; operation < kAluMnemonics.size(); ++operation) {
        for (std::size_t source = 0; source < kRegisters8.size(); ++source) {
            const auto opcode = static_cast<std::uint8_t>(0x80U + operation * 8U + source);
            const bool reads_memory = source == 6U;
            const std::uint8_t cycles = reads_memory ? 8U : 4U;
            Category category = Category::Arithmetic;
            if (operation == 4U || operation == 5U || operation == 6U) {
                category = Category::Logical;
            } else if (operation == 7U) {
                category = Category::Compare;
            }
            const std::uint8_t flags_read = (operation == 1U || operation == 3U) ? kFlagC : 0U;
            set(table, opcode, false, std::string(kAluMnemonics[operation]),
                "A, " + std::string(kRegisters8[source]), 1U, cycles, cycles,
                category, flags_read, kAllFlags, Flow::Sequential,
                reads_memory, false);
        }
    }

    const std::array<std::string_view, 4> stack_pairs{"BC", "DE", "HL", "AF"};
    for (std::size_t condition = 0; condition < kConditions.size(); ++condition) {
        const auto condition_offset = static_cast<std::uint8_t>(condition * 8U);
        const std::uint8_t flag = (condition == 0U || condition == 1U) ? kFlagZ : kFlagC;
        set(table, static_cast<std::uint8_t>(0xC0U + condition_offset), false,
            "RET", std::string(kConditions[condition]), 1U, 20U, 8U,
            Category::Return, flag, 0U, Flow::ConditionalReturn, true, false);
        set(table, static_cast<std::uint8_t>(0xC2U + condition_offset), false,
            "JP", std::string(kConditions[condition]) + ", a16", 3U, 16U, 12U,
            Category::Branch, flag, 0U, Flow::ConditionalBranch);
        set(table, static_cast<std::uint8_t>(0xC4U + condition_offset), false,
            "CALL", std::string(kConditions[condition]) + ", a16", 3U, 24U, 12U,
            Category::Call, flag, 0U, Flow::ConditionalCall, false, true);
    }

    for (std::size_t pair = 0; pair < stack_pairs.size(); ++pair) {
        const auto pair_offset = static_cast<std::uint8_t>(pair * 0x10U);
        const auto pop = static_cast<std::uint8_t>(0xC1U + pair_offset);
        const auto push = static_cast<std::uint8_t>(0xC5U + pair_offset);
        set(table, pop, false, "POP", std::string(stack_pairs[pair]), 1U, 12U, 12U,
            Category::Stack, 0U, pair == 3U ? kAllFlags : 0U, Flow::Sequential,
            true, false);
        set(table, push, false, "PUSH", std::string(stack_pairs[pair]), 1U, 16U, 16U,
            Category::Stack, 0U, 0U, Flow::Sequential, false, true);
    }

    const std::array<std::string_view, 8> immediate_alu_operands{
        "A, d8", "A, d8", "A, d8", "A, d8", "d8", "d8", "d8", "A, d8",
    };
    for (std::size_t operation = 0; operation < kAluMnemonics.size(); ++operation) {
        const auto opcode = static_cast<std::uint8_t>(0xC6U + operation * 8U);
        Category category = Category::Arithmetic;
        if (operation >= 4U && operation <= 6U) {
            category = Category::Logical;
        } else if (operation == 7U) {
            category = Category::Compare;
        }
        const std::uint8_t flags_read = (operation == 1U || operation == 3U) ? kFlagC : 0U;
        set(table, opcode, false, std::string(kAluMnemonics[operation]),
            std::string(immediate_alu_operands[operation]), 2U, 8U, 8U,
            category, flags_read, kAllFlags);
    }

    for (std::size_t vector = 0; vector < 8U; ++vector) {
        const auto opcode = static_cast<std::uint8_t>(0xC7U + vector * 8U);
        const auto target = static_cast<std::uint16_t>(vector * 8U);
        const std::string target_text = "$" + [&] {
            constexpr char digits[] = "0123456789ABCDEF";
            std::string result(2U, '0');
            result[0] = digits[(target >> 4U) & 0x0FU];
            result[1] = digits[target & 0x0FU];
            return result;
        }();
        set(table, opcode, false, "RST", target_text, 1U, 16U, 16U,
            Category::Call, 0U, 0U, Flow::Reset, false, true, true, true, target);
    }

    set(table, 0xC3U, false, "JP", "a16", 3U, 16U, 16U, Category::Branch,
        0U, 0U, Flow::UnconditionalBranch);
    set(table, 0xC9U, false, "RET", "", 1U, 16U, 16U, Category::Return,
        0U, 0U, Flow::Return, true, false);
    set(table, 0xCBU, false, "PREFIX", "CB", 2U, 8U, 8U,
        Category::Control);
    set(table, 0xCDU, false, "CALL", "a16", 3U, 24U, 24U,
        Category::Call, 0U, 0U, Flow::Call, false, true);
    set(table, 0xD9U, false, "RETI", "", 1U, 16U, 16U,
        Category::Return, 0U, 0U, Flow::InterruptReturn, true, false);
    set(table, 0xE0U, false, "LDH", "[a8], A", 2U, 12U, 12U,
        Category::Load, 0U, 0U, Flow::Sequential, false, true);
    set(table, 0xE2U, false, "LDH", "[C], A", 1U, 8U, 8U,
        Category::Load, 0U, 0U, Flow::Sequential, false, true);
    set(table, 0xE8U, false, "ADD", "SP, e8", 2U, 16U, 16U,
        Category::Arithmetic, 0U, kAllFlags);
    set(table, 0xE9U, false, "JP", "HL", 1U, 4U, 4U,
        Category::Branch, 0U, 0U, Flow::IndirectJump);
    set(table, 0xEAU, false, "LD", "[a16], A", 3U, 16U, 16U,
        Category::Load, 0U, 0U, Flow::Sequential, false, true);
    set(table, 0xF0U, false, "LDH", "A, [a8]", 2U, 12U, 12U,
        Category::Load, 0U, 0U, Flow::Sequential, true, false);
    set(table, 0xF2U, false, "LDH", "A, [C]", 1U, 8U, 8U,
        Category::Load, 0U, 0U, Flow::Sequential, true, false);
    set(table, 0xF3U, false, "DI", "", 1U, 4U, 4U,
        Category::Interrupt);
    set(table, 0xF8U, false, "LD", "HL, SP+e8", 2U, 12U, 12U,
        Category::Load, 0U, static_cast<std::uint8_t>(kFlagZ | kFlagN | kFlagH | kFlagC));
    set(table, 0xF9U, false, "LD", "SP, HL", 1U, 8U, 8U,
        Category::Load);
    set(table, 0xFAU, false, "LD", "A, [a16]", 3U, 16U, 16U,
        Category::Load, 0U, 0U, Flow::Sequential, true, false);
    set(table, 0xFBU, false, "EI", "", 1U, 4U, 4U, Category::Interrupt);

    return table;
}

OpcodeTable make_cb_table() {
    OpcodeTable table{};
    initialize_illegal_table(table, true);

    for (std::size_t opcode = 0; opcode < table.size(); ++opcode) {
        const std::size_t group = opcode >> 6U;
        const std::size_t operation = (opcode >> 3U) & 0x07U;
        const std::size_t target = opcode & 0x07U;
        const bool indirect = target == 6U;
        const std::string target_name(kRegisters8[target]);
        const auto op = static_cast<std::uint8_t>(opcode);
        if (group == 0U) {
            const bool uses_carry = operation == 2U || operation == 3U;
            const std::uint8_t cycles = indirect ? 16U : 8U;
            const Category category = operation <= 3U ? Category::Rotate
                : operation == 6U ? Category::Misc : Category::Shift;
            set(table, op, true, std::string(kCbMnemonics[operation]), target_name,
                2U, cycles, cycles, category, uses_carry ? kFlagC : 0U, kAllFlags,
                Flow::Sequential, indirect, indirect);
        } else if (group == 1U) {
            const auto bit_index = static_cast<unsigned>((opcode >> 3U) & 0x07U);
            const auto bit_text = std::to_string(bit_index);
            const std::uint8_t cycles = indirect ? 12U : 8U;
            set(table, op, true, "BIT", bit_text + ", " + target_name, 2U,
                cycles, cycles, Category::Bit, 0U,
                static_cast<std::uint8_t>(kFlagZ | kFlagN | kFlagH),
                Flow::Sequential, indirect, false);
        } else {
            const auto bit_index = static_cast<unsigned>((opcode >> 3U) & 0x07U);
            const auto bit_text = std::to_string(bit_index);
            const std::uint8_t cycles = indirect ? 16U : 8U;
            const bool set_bit = group == 3U;
            set(table, op, true, set_bit ? "SET" : "RES",
                bit_text + ", " + target_name, 2U, cycles, cycles, Category::Bit,
                0U, 0U, Flow::Sequential, indirect, indirect);
        }
    }
    return table;
}

}  // namespace

const OpcodeTable& base_opcode_table() noexcept {
    static const OpcodeTable table = make_base_table();
    return table;
}

const OpcodeTable& cb_opcode_table() noexcept {
    static const OpcodeTable table = make_cb_table();
    return table;
}

const OpcodeMetadata& base_opcode_metadata(const std::uint8_t opcode) noexcept {
    return base_opcode_table()[opcode];
}

const OpcodeMetadata& cb_opcode_metadata(const std::uint8_t opcode) noexcept {
    return cb_opcode_table()[opcode];
}

}  // namespace tool::cpu
