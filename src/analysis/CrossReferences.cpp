#include "tool/analysis/CrossReferences.h"

#include "tool/analysis/CodeDataAnalyzer.h"
#include "tool/analysis/ControlFlowGraph.h"
#include "tool/analysis/FunctionDiscovery.h"
#include "tool/cpu/Instruction.h"
#include "tool/memory/MemoryMap.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace tool::analysis {
namespace {

using CodeKey = std::pair<std::uint16_t, std::uint16_t>;
using RefKey = std::tuple<XrefKind, std::uint16_t, std::uint16_t, XrefAddressSpace,
                          std::uint16_t, std::uint16_t, std::string, std::string>;

std::string hex_value(const std::uint16_t value, const int digits) {
    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0') << std::setw(digits) << value;
    return output.str();
}

std::optional<std::uint16_t> parse_hex_at(const std::string_view text,
                                          const std::size_t start,
                                          std::size_t& end) {
    if (start >= text.size() || text[start] != '$') {
        return std::nullopt;
    }
    std::size_t cursor = start + 1U;
    const std::size_t digits_start = cursor;
    while (cursor < text.size() &&
           ((text[cursor] >= '0' && text[cursor] <= '9') ||
            (text[cursor] >= 'A' && text[cursor] <= 'F') ||
            (text[cursor] >= 'a' && text[cursor] <= 'f'))) {
        ++cursor;
    }
    if (cursor == digits_start || cursor - digits_start > 4U) {
        return std::nullopt;
    }
    unsigned value{};
    const auto parsed = std::from_chars(text.data() + digits_start, text.data() + cursor,
                                        value, 16);
    if (parsed.ec != std::errc{}) {
        return std::nullopt;
    }
    end = cursor;
    return static_cast<std::uint16_t>(value);
}

std::optional<std::uint16_t> absolute_memory_address(const cpu::Instruction& instruction) {
    const std::size_t open = instruction.operands.find('[');
    if (open == std::string::npos) {
        return std::nullopt;
    }
    const std::size_t close = instruction.operands.find(']', open + 1U);
    if (close == std::string::npos) {
        return std::nullopt;
    }
    const std::string_view expression(instruction.operands.data() + open + 1U,
                                      close - open - 1U);
    std::size_t end{};
    const auto first = parse_hex_at(expression, 0U, end);
    if (!first.has_value()) {
        return std::nullopt;
    }
    if (end < expression.size() && expression[end] == '+') {
        std::size_t second_end{};
        const auto second = parse_hex_at(expression, end + 1U, second_end);
        if (!second.has_value() || second_end != expression.size()) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(*first + *second);
    }
    if (end != expression.size()) {
        return std::nullopt;
    }
    return first;
}

std::optional<std::uint16_t> mapped_rom_bank(const rom::Rom& image,
                                             const std::uint16_t source_bank,
                                             const std::uint16_t address) {
    if (address <= 0x3FFFU) {
        return static_cast<std::uint16_t>(0U);
    }
    if (address > 0x7FFFU) {
        return std::nullopt;
    }
    const std::uint16_t selected = source_bank == 0U ? 1U : source_bank;
    return image.bank(selected).has_value() ? std::optional<std::uint16_t>(selected)
                                             : std::nullopt;
}

std::optional<XrefLocation> rom_location(const rom::Rom& image,
                                         const std::uint16_t source_bank,
                                         const std::uint16_t address) {
    const auto bank_index = mapped_rom_bank(image, source_bank, address);
    if (!bank_index.has_value()) {
        return std::nullopt;
    }
    const auto bank = image.bank(*bank_index);
    if (!bank.has_value()) {
        return std::nullopt;
    }
    const auto offset = bank->file_offset_for_cpu_address(address);
    if (!offset.has_value() || *offset >= image.actual_size_bytes()) {
        return std::nullopt;
    }
    return XrefLocation{XrefAddressSpace::Rom, *bank_index, address, *offset};
}

XrefLocation make_source(const rom::Rom& image, const std::uint16_t bank_index,
                         const std::uint16_t address) {
    const auto bank = image.bank(bank_index);
    const auto offset = bank.has_value() ? bank->file_offset_for_cpu_address(address)
                                         : std::nullopt;
    return {XrefAddressSpace::Rom, bank_index, address, offset};
}

XrefLocation memory_location(const std::uint16_t source_bank,
                             const std::uint16_t address,
                             const bool writes_memory) {
    memory::MemoryMapContext context;
    context.switchable_rom_bank = source_bank == 0U
        ? std::optional<std::uint16_t>(std::uint16_t{1U})
        : std::optional<std::uint16_t>(source_bank);
    const memory::MemoryMapping mapping = memory::map_memory_address(address, context);

    if ((mapping.region == memory::MemoryRegion::FixedRom ||
         mapping.region == memory::MemoryRegion::SwitchableRom) && writes_memory) {
        return {XrefAddressSpace::Mapper, std::nullopt, address, std::nullopt};
    }
    if (mapping.region == memory::MemoryRegion::FixedRom ||
        mapping.region == memory::MemoryRegion::SwitchableRom) {
        return {XrefAddressSpace::Rom, mapping.bank, address, std::nullopt};
    }
    if (mapping.region == memory::MemoryRegion::IoRegisters ||
        mapping.region == memory::MemoryRegion::InterruptEnable) {
        return {XrefAddressSpace::Hardware, std::nullopt, address, std::nullopt};
    }
    if (mapping.region == memory::MemoryRegion::Unusable) {
        return {XrefAddressSpace::Unusable, std::nullopt, address, std::nullopt};
    }
    return {XrefAddressSpace::Ram, mapping.bank, address, std::nullopt};
}

std::string hardware_name(const std::uint16_t address) {
    const memory::HardwareRegisterInfo* info = memory::hardware_register_info(address);
    return info == nullptr ? "IO" : std::string(info->name);
}

bool is_direct_control_target(const cpu::ControlFlowType flow) noexcept {
    return flow == cpu::ControlFlowType::ConditionalBranch ||
           flow == cpu::ControlFlowType::UnconditionalBranch ||
           flow == cpu::ControlFlowType::Call ||
           flow == cpu::ControlFlowType::ConditionalCall ||
           flow == cpu::ControlFlowType::Reset;
}

bool is_call(const cpu::ControlFlowType flow) noexcept {
    return flow == cpu::ControlFlowType::Call ||
           flow == cpu::ControlFlowType::ConditionalCall ||
           flow == cpu::ControlFlowType::Reset;
}

RefKey key_for(const CrossReference& reference) {
    return {reference.kind,
            reference.source.bank.value_or(0U), reference.source.address,
            reference.target.space, reference.target.bank.value_or(0xFFFFU),
            reference.target.address, reference.source_function_id,
            reference.target_function_id};
}

std::uint8_t confidence_for_data(const RegionClassification classification) noexcept {
    switch (classification) {
        case RegionClassification::Data: return 70U;
        case RegionClassification::PossibleData: return 55U;
        case RegionClassification::Unknown: return 25U;
        default: return 15U;
    }
}

}  // namespace

CrossReferenceResult build_cross_references(const rom::Rom& image,
                                            const std::stop_token stop_token) {
    CrossReferenceResult result;
    const FunctionDiscoveryResult functions = discover_functions(image, stop_token);
    if (functions.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }
    result.functions_analyzed = functions.functions.size();

    const ControlFlowGraphResult graphs = build_control_flow_graphs(
        image, functions.functions, stop_token);
    if (graphs.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }
    result.instructions_analyzed = graphs.instructions_analyzed;

    std::vector<ClassificationRecord> classifications;
    const ReachabilityStats classification_stats = analyze_reachable_code(
        image, [&classifications](const ClassificationRecord& record) {
            classifications.push_back(record);
            return true;
        }, stop_token);
    if (classification_stats.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }

    std::vector<RegionClassification> class_by_offset(
        image.actual_size_bytes(), RegionClassification::Unknown);
    std::vector<std::uint8_t> code_bytes(image.actual_size_bytes(), 0U);
    std::map<CodeKey, std::uint8_t> known_code;
    for (const ClassificationRecord& record : classifications) {
        const std::size_t end = std::min(image.actual_size_bytes(),
                                         record.rom_offset + record.length);
        for (std::size_t offset = record.rom_offset; offset < end; ++offset) {
            class_by_offset[offset] = record.classification;
        }
        if (record.instruction.has_value() &&
            (record.classification == RegionClassification::Code ||
             record.classification == RegionClassification::PossibleCode)) {
            known_code[{record.bank, record.cpu_address}] = record.confidence_percent;
            for (std::size_t offset = record.rom_offset;
                 offset < std::min(end, record.rom_offset + record.instruction->length);
                 ++offset) {
                code_bytes[offset] = 1U;
            }
        }
    }

    std::map<CodeKey, std::string> function_at;
    for (const FunctionInfo& function : functions.functions) {
        function_at[{function.bank, function.cpu_address}] = function.id;
    }
    for (const ControlFlowGraph& graph : graphs.graphs) {
        for (const BasicBlock& block : graph.blocks) {
            const auto bank = image.bank(block.bank);
            for (const cpu::Instruction& instruction : block.instructions) {
                known_code.try_emplace({block.bank, instruction.address},
                                       static_cast<std::uint8_t>(85U));
                if (!bank.has_value()) {
                    continue;
                }
                const auto offset = bank->file_offset_for_cpu_address(instruction.address);
                if (!offset.has_value()) {
                    continue;
                }
                const std::size_t end = std::min(code_bytes.size(), *offset + instruction.length);
                for (std::size_t current = *offset; current < end; ++current) {
                    code_bytes[current] = 1U;
                }
            }
        }
    }
    std::map<RefKey, CrossReference> unique_references;
    const auto add_reference = [&](CrossReference reference) {
        const RefKey key = key_for(reference);
        const auto [found, inserted] = unique_references.try_emplace(key, std::move(reference));
        if (!inserted) {
            found->second.confidence_percent = std::max(found->second.confidence_percent,
                                                        reference.confidence_percent);
            found->second.candidate = found->second.candidate || reference.candidate;
        }
    };

    for (const ControlFlowGraph& graph : graphs.graphs) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            return result;
        }
        for (const BasicBlock& block : graph.blocks) {
            for (const cpu::Instruction& instruction : block.instructions) {
                const XrefLocation source = make_source(image, block.bank, instruction.address);
                const std::string& source_function = graph.function_id;

                if (is_direct_control_target(instruction.control_flow) &&
                    instruction.branch_target.has_value()) {
                    const auto target = rom_location(image, block.bank,
                                                     *instruction.branch_target);
                    if (target.has_value()) {
                        const auto function = function_at.find(
                            {*target->bank, target->address});
                        const std::string target_function = function == function_at.end()
                            ? std::string{} : function->second;
                        const std::uint8_t confidence = target->bank == block.bank ? 90U : 85U;
                        const bool known_target = known_code.contains(
                            {*target->bank, target->address});
                        add_reference({XrefKind::CodeToCode, source, *target, source_function,
                                       target_function, instruction.mnemonic, confidence,
                                       !known_target});
                        if (target->bank != block.bank) {
                            add_reference({XrefKind::BankToBank, source, *target, source_function,
                                           target_function, instruction.mnemonic, confidence, false});
                        }
                        if (is_call(instruction.control_flow) && function != function_at.end()) {
                            add_reference({XrefKind::FunctionToFunction, source, *target,
                                           source_function, target_function, instruction.mnemonic,
                                           confidence, false});
                        }
                    }
                }

                const auto memory_address = absolute_memory_address(instruction);
                if (memory_address.has_value()) {
                    XrefLocation target = memory_location(block.bank, *memory_address,
                                                          instruction.writes_memory);
                    XrefKind kind = XrefKind::CodeToRam;
                    std::uint8_t confidence = 90U;
                    bool candidate = false;
                    if (target.space == XrefAddressSpace::Rom) {
                        kind = XrefKind::CodeToData;
                        const auto mapped = rom_location(image, block.bank, *memory_address);
                        if (mapped.has_value()) {
                            target = *mapped;
                            const RegionClassification classification =
                                class_by_offset[*mapped->rom_offset];
                            confidence = confidence_for_data(classification);
                            candidate = classification != RegionClassification::Data &&
                                        classification != RegionClassification::PossibleData;
                        } else {
                            confidence = 20U;
                            candidate = true;
                        }
                    } else if (target.space == XrefAddressSpace::Hardware) {
                        kind = XrefKind::CodeToHardwareRegister;
                    } else if (target.space == XrefAddressSpace::Mapper) {
                        kind = XrefKind::CodeToMapperRegister;
                    } else if (target.space == XrefAddressSpace::Unusable) {
                        kind = XrefKind::CodeToUnusable;
                    }
                    add_reference({kind, source, target, source_function, {},
                                   instruction.mnemonic, confidence, candidate});
                }
            }
        }
    }

    // Data pointers are candidates: the bank state at runtime is not known, and
    // arbitrary unknown bytes can resemble little-endian code addresses.
    for (std::size_t bank_index = 0; bank_index < image.actual_bank_count(); ++bank_index) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            return result;
        }
        const auto bank = image.bank(static_cast<std::uint16_t>(bank_index));
        if (!bank.has_value()) {
            continue;
        }
        const std::span<const std::uint8_t> bytes = bank->bytes();
        const std::uint32_t base = bank_index == 0U ? 0U : 0x4000U;
        for (std::size_t local = 0; local + 1U < bytes.size(); ++local) {
            const std::size_t offset = bank->file_offset() + local;
            if (offset + 1U >= code_bytes.size() || code_bytes[offset] != 0U ||
                code_bytes[offset + 1U] != 0U) {
                continue;
            }
            const std::uint16_t target_address = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(bytes[local]) |
                (static_cast<std::uint16_t>(bytes[local + 1U]) << 8U));
            const auto target_bank = mapped_rom_bank(image,
                static_cast<std::uint16_t>(bank_index), target_address);
            if (!target_bank.has_value() ||
                !known_code.contains({*target_bank, target_address})) {
                continue;
            }
            const auto target = rom_location(image, static_cast<std::uint16_t>(bank_index),
                                             target_address);
            if (!target.has_value()) {
                continue;
            }
            const std::uint8_t confidence = confidence_for_data(class_by_offset[offset]);
            const std::uint16_t source_address = static_cast<std::uint16_t>(base + local);
            add_reference({XrefKind::DataToCode,
                           {XrefAddressSpace::Rom, static_cast<std::uint16_t>(bank_index),
                            source_address, offset},
                           *target, {}, function_at.contains({*target->bank, target->address})
                               ? function_at.at({*target->bank, target->address}) : std::string{},
                           "DW", confidence, true});
        }
    }

    result.references.reserve(unique_references.size());
    for (auto& [key, reference] : unique_references) {
        static_cast<void>(key);
        result.references.push_back(std::move(reference));
    }
    return result;
}

std::string_view xref_kind_name(const XrefKind kind) noexcept {
    switch (kind) {
        case XrefKind::CodeToCode: return "code->code";
        case XrefKind::CodeToData: return "code->data";
        case XrefKind::DataToCode: return "data->code";
        case XrefKind::CodeToRam: return "code->RAM";
        case XrefKind::CodeToHardwareRegister: return "code->hardware";
        case XrefKind::CodeToMapperRegister: return "code->mapper";
        case XrefKind::CodeToUnusable: return "code->unusable";
        case XrefKind::BankToBank: return "bank->bank";
        case XrefKind::FunctionToFunction: return "function->function";
    }
    return "unknown";
}

std::string_view xref_address_space_name(const XrefAddressSpace space) noexcept {
    switch (space) {
        case XrefAddressSpace::Rom: return "ROM";
        case XrefAddressSpace::Ram: return "RAM";
        case XrefAddressSpace::Hardware: return "hardware";
        case XrefAddressSpace::Mapper: return "mapper";
        case XrefAddressSpace::Unusable: return "unusable";
    }
    return "unknown";
}

std::string format_xref_location(const XrefLocation& location) {
    if (location.space == XrefAddressSpace::Rom && location.bank.has_value()) {
        return "B" + hex_value(*location.bank, 4) + ":$" + hex_value(location.address, 4);
    }
    std::string label(xref_address_space_name(location.space));
    if (location.space == XrefAddressSpace::Hardware) {
        label += "(" + hardware_name(location.address) + ")";
    }
    return label + ":$" + hex_value(location.address, 4);
}

std::string format_cross_reference(const CrossReference& reference) {
    std::ostringstream output;
    output << format_xref_location(reference.source) << " --"
           << xref_kind_name(reference.kind) << "--> "
           << format_xref_location(reference.target) << ' '
           << static_cast<unsigned>(reference.confidence_percent) << "% ["
           << reference.mnemonic << ']';
    if (reference.candidate) {
        output << " candidate";
    }
    if (!reference.source_function_id.empty() || !reference.target_function_id.empty()) {
        output << " {" << (reference.source_function_id.empty() ? "?" : reference.source_function_id)
               << " -> " << (reference.target_function_id.empty() ? "?" : reference.target_function_id)
               << '}';
    }
    return output.str();
}

std::vector<const CrossReference*> find_references_to(const CrossReferenceResult& result,
                                                      const XrefLocation& target) {
    std::vector<const CrossReference*> matches;
    for (const CrossReference& reference : result.references) {
        if (reference.target.space == target.space &&
            reference.target.bank == target.bank && reference.target.address == target.address) {
            matches.push_back(&reference);
        }
    }
    return matches;
}

}  // namespace tool::analysis
