#include "tool/analysis/FunctionDiscovery.h"

#include "tool/cpu/SM83.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tool::analysis {
namespace {

using FunctionKey = std::pair<std::uint16_t, std::uint16_t>;

constexpr std::uint8_t kResetConfidence = 100U;
constexpr std::uint8_t kInterruptConfidence = 85U;
constexpr std::uint8_t kDirectCallConfidence = 95U;
constexpr std::uint8_t kBranchConfidence = 95U;
constexpr std::uint8_t kFallthroughConfidence = 90U;
constexpr std::uint8_t kAssumedBankConfidence = 85U;
constexpr std::size_t kHeaderDataBegin = 0x0104U;
constexpr std::size_t kHeaderDataEnd = 0x0150U;

struct BankLocation {
    std::uint16_t bank{};
    bool assumes_default_bank{};
};

struct PendingAddress {
    std::uint16_t bank{};
    std::uint16_t address{};
    std::uint8_t confidence{};
};

struct InternalFunction {
    FunctionInfo info;
    std::set<std::string> callers;
    std::set<std::string> callees;
};

std::uint8_t evidence_priority(const FunctionStartEvidence evidence) noexcept {
    switch (evidence) {
        case FunctionStartEvidence::ResetEntry: return 3U;
        case FunctionStartEvidence::InterruptVector: return 2U;
        case FunctionStartEvidence::DirectCall: return 1U;
    }
    return 0U;
}

std::string format_hex(const std::uint16_t value) {
    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0') << std::setw(4) << value;
    return output.str();
}

std::string function_id(const std::uint16_t bank, const std::uint16_t address) {
    return "fn_b" + format_hex(bank) + "_" + format_hex(address);
}

std::string generated_name(const std::uint16_t bank, const std::uint16_t address,
                           const FunctionStartEvidence evidence) {
    if (evidence == FunctionStartEvidence::ResetEntry && bank == 0U && address == 0x0100U) {
        return "entry_0100";
    }
    if (evidence == FunctionStartEvidence::InterruptVector && bank == 0U) {
        switch (address) {
            case 0x0040U: return "irq_vblank";
            case 0x0048U: return "irq_lcd_stat";
            case 0x0050U: return "irq_timer";
            case 0x0058U: return "irq_serial";
            case 0x0060U: return "irq_joypad";
            default: break;
        }
    }
    if (bank == 0U || address < 0x4000U) {
        return "sub_" + format_hex(address);
    }
    return "sub_b" + format_hex(bank) + "_" + format_hex(address);
}

std::optional<std::size_t> rom_offset_for(const rom::Rom& image,
                                         const std::uint16_t bank_index,
                                         const std::uint16_t address) {
    const auto bank = image.bank(bank_index);
    if (!bank.has_value()) {
        return std::nullopt;
    }
    return bank->file_offset_for_cpu_address(address);
}

bool is_header_data(const std::size_t rom_offset) noexcept {
    return rom_offset >= kHeaderDataBegin && rom_offset < kHeaderDataEnd;
}

std::optional<BankLocation> bank_for_target(const rom::Rom& image,
                                           const std::uint16_t source_bank,
                                           const std::uint16_t target) {
    if (target <= 0x3FFFU) {
        return BankLocation{0U, false};
    }
    if (target > 0x7FFFU || image.actual_bank_count() < 2U) {
        return std::nullopt;
    }
    if (source_bank == 0U) {
        return BankLocation{1U, true};
    }
    return BankLocation{source_bank, false};
}

std::optional<BankLocation> bank_for_fallthrough(const rom::Rom& image,
                                                 const std::uint16_t source_bank,
                                                 const std::uint32_t next_address) {
    if (next_address <= 0x3FFFU) {
        return BankLocation{0U, false};
    }
    if (next_address == 0x4000U && source_bank == 0U &&
        image.actual_bank_count() >= 2U) {
        return BankLocation{1U, true};
    }
    if (next_address <= 0x7FFFU && source_bank != 0U) {
        return BankLocation{source_bank, false};
    }
    return std::nullopt;
}

}  // namespace

FunctionDiscoveryResult discover_functions(const rom::Rom& image,
                                           const std::stop_token stop_token) {
    FunctionDiscoveryResult result;
    std::map<FunctionKey, InternalFunction> functions;
    std::deque<FunctionKey> pending_functions;
    std::map<FunctionKey, std::unordered_map<std::size_t, std::uint8_t>> visited_by_function;
    std::map<FunctionKey, std::unordered_map<std::size_t, std::uint8_t>> processed_by_function;

    const auto ensure_function = [&](const std::uint16_t bank, const std::uint16_t address,
                                     const std::uint8_t confidence,
                                     const FunctionStartEvidence evidence)
        -> std::optional<FunctionKey> {
        const auto offset = rom_offset_for(image, bank, address);
        if (!offset.has_value() || is_header_data(*offset)) {
            return std::nullopt;
        }
        const FunctionKey key{bank, address};
        auto [found, inserted] = functions.try_emplace(key);
        InternalFunction& function = found->second;
        if (inserted) {
            function.info.id = function_id(bank, address);
            function.info.name = generated_name(bank, address, evidence);
            function.info.bank = bank;
            function.info.cpu_address = address;
            function.info.confidence_percent = confidence;
            function.info.start_evidence = evidence;
            pending_functions.push_back(key);
        } else {
            bool changed = false;
            if (confidence > function.info.confidence_percent) {
                function.info.confidence_percent = confidence;
                changed = true;
            }
            if (evidence_priority(evidence) > evidence_priority(function.info.start_evidence)) {
                function.info.start_evidence = evidence;
                function.info.name = generated_name(bank, address, evidence);
            }
            if (changed) {
                pending_functions.push_back(key);
            }
        }
        return key;
    };

    static constexpr std::array<std::uint16_t, 5> kInterruptVectors{
        0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U};
    static_cast<void>(ensure_function(0U, 0x0100U, kResetConfidence,
                                      FunctionStartEvidence::ResetEntry));
    for (const std::uint16_t address : kInterruptVectors) {
        static_cast<void>(ensure_function(0U, address, kInterruptConfidence,
                                          FunctionStartEvidence::InterruptVector));
    }

    while (!pending_functions.empty()) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            break;
        }
        const FunctionKey current_key = pending_functions.front();
        pending_functions.pop_front();
        const auto current_it = functions.find(current_key);
        if (current_it == functions.end()) {
            continue;
        }
        const std::uint8_t entry_confidence = current_it->second.info.confidence_percent;
        const std::string caller_id = current_it->second.info.id;
        std::deque<PendingAddress> pending_addresses;
        auto& best_confidence = visited_by_function[current_key];
        const auto entry_offset = rom_offset_for(image, current_key.first, current_key.second);
        if (!entry_offset.has_value()) {
            continue;
        }
        const auto entry_seen = best_confidence.find(*entry_offset);
        if (entry_seen != best_confidence.end() && entry_seen->second >= entry_confidence) {
            continue;
        }
        best_confidence[*entry_offset] = entry_confidence;
        pending_addresses.push_back({current_key.first, current_key.second, entry_confidence});

        const auto offer_address = [&](const std::uint16_t bank, const std::uint16_t address,
                                       const std::uint8_t confidence) {
            const auto offset = rom_offset_for(image, bank, address);
            if (!offset.has_value() || *offset >= image.actual_size_bytes() ||
                is_header_data(*offset)) {
                return;
            }
            const auto known_start = functions.find(FunctionKey{bank, address});
            if (known_start != functions.end() && !(known_start->first == current_key)) {
                return;
            }
            const auto seen = best_confidence.find(*offset);
            if (seen != best_confidence.end() && seen->second >= confidence) {
                return;
            }
            best_confidence[*offset] = confidence;
            pending_addresses.push_back({bank, address, confidence});
        };

        while (!pending_addresses.empty()) {
            if (stop_token.stop_requested()) {
                result.cancelled = true;
                break;
            }
            const PendingAddress current = pending_addresses.front();
            pending_addresses.pop_front();
            const auto bank = image.bank(current.bank);
            if (!bank.has_value()) {
                continue;
            }
            const auto rom_offset = bank->file_offset_for_cpu_address(current.address);
            if (!rom_offset.has_value() || *rom_offset < bank->file_offset()) {
                continue;
            }
            const std::size_t local_offset = *rom_offset - bank->file_offset();
            const std::span<const std::uint8_t> bytes = bank->bytes();
            if (local_offset >= bytes.size()) {
                continue;
            }
            const std::uint8_t previous_confidence = best_confidence[*rom_offset];
            if (current.confidence < previous_confidence) {
                continue;
            }
            auto& processed = processed_by_function[current_key];
            const auto processed_at = processed.find(*rom_offset);
            if (processed_at != processed.end() && processed_at->second >= current.confidence) {
                continue;
            }
            const bool first_visit = processed_at == processed.end();
            processed[*rom_offset] = current.confidence;
            const auto decoded = cpu::decode_sm83_instruction(
                bytes.subspan(local_offset), current.address);
            if (!decoded.success()) {
                continue;
            }
            InternalFunction& current_function = functions.at(current_key);
            if (first_visit) {
                ++result.analyzed_instructions;
                ++current_function.info.reachable_instruction_count;
            }

            const cpu::Instruction& instruction = *decoded.instruction;
            const std::uint32_t next_address =
                static_cast<std::uint32_t>(current.address) + instruction.length;
            const auto offer_fallthrough = [&]() {
                const auto next = bank_for_fallthrough(image, current.bank, next_address);
                if (!next.has_value()) {
                    return;
                }
                const std::uint8_t edge_confidence = next->assumes_default_bank
                    ? kAssumedBankConfidence
                    : kFallthroughConfidence;
                offer_address(next->bank, static_cast<std::uint16_t>(next_address),
                              std::min(current.confidence, edge_confidence));
            };
            const auto target_location = [&]() -> std::optional<BankLocation> {
                if (!instruction.branch_target.has_value()) {
                    return std::nullopt;
                }
                return bank_for_target(image, current.bank, *instruction.branch_target);
            };
            const auto offer_branch_target = [&]() {
                const auto target = target_location();
                if (!target.has_value() || !instruction.branch_target.has_value()) {
                    return;
                }
                const std::uint8_t edge_confidence = target->assumes_default_bank
                    ? kAssumedBankConfidence
                    : kBranchConfidence;
                offer_address(target->bank, *instruction.branch_target,
                              std::min(current.confidence, edge_confidence));
            };
            const auto discover_callee = [&]() {
                const auto target = target_location();
                if (!target.has_value() || !instruction.branch_target.has_value()) {
                    return;
                }
                const std::uint8_t edge_confidence = target->assumes_default_bank
                    ? kAssumedBankConfidence
                    : kDirectCallConfidence;
                const auto callee_key = ensure_function(
                    target->bank, *instruction.branch_target,
                    std::min(current.confidence, edge_confidence),
                    FunctionStartEvidence::DirectCall);
                if (!callee_key.has_value()) {
                    return;
                }
                const auto callee = functions.find(*callee_key);
                if (callee != functions.end()) {
                    current_function.callees.insert(callee->second.info.id);
                    callee->second.callers.insert(caller_id);
                }
            };

            switch (instruction.control_flow) {
                case cpu::ControlFlowType::Sequential:
                    offer_fallthrough();
                    break;
                case cpu::ControlFlowType::ConditionalBranch:
                    offer_branch_target();
                    offer_fallthrough();
                    break;
                case cpu::ControlFlowType::UnconditionalBranch:
                    offer_branch_target();
                    break;
                case cpu::ControlFlowType::Call:
                case cpu::ControlFlowType::ConditionalCall:
                case cpu::ControlFlowType::Reset:
                    discover_callee();
                    offer_fallthrough();
                    break;
                case cpu::ControlFlowType::ConditionalReturn:
                case cpu::ControlFlowType::IndirectCall:
                    offer_fallthrough();
                    break;
                case cpu::ControlFlowType::Return:
                case cpu::ControlFlowType::InterruptReturn:
                case cpu::ControlFlowType::IndirectJump:
                case cpu::ControlFlowType::Halt:
                case cpu::ControlFlowType::Stop:
                case cpu::ControlFlowType::Unknown:
                    break;
            }
        }
        if (result.cancelled) {
            break;
        }
    }

    result.functions.reserve(functions.size());
    for (auto& [key, function] : functions) {
        static_cast<void>(key);
        function.info.callers.assign(function.callers.begin(), function.callers.end());
        function.info.callees.assign(function.callees.begin(), function.callees.end());
        result.functions.push_back(std::move(function.info));
    }
    return result;
}

std::string_view function_start_evidence_name(const FunctionStartEvidence evidence) noexcept {
    switch (evidence) {
        case FunctionStartEvidence::ResetEntry: return "reset entry";
        case FunctionStartEvidence::InterruptVector: return "interrupt vector";
        case FunctionStartEvidence::DirectCall: return "direct CALL/RST target";
    }
    return "unknown";
}

}  // namespace tool::analysis
