#include "tool/analysis/CodeDataAnalyzer.h"

#include "tool/cpu/SM83.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <span>
#include <utility>
#include <vector>

namespace tool::analysis {
namespace {

constexpr std::uint8_t kResetConfidence = 100U;
constexpr std::uint8_t kInterruptConfidence = 85U;
constexpr std::uint8_t kDirectEdgeConfidence = 95U;
constexpr std::uint8_t kFallthroughConfidence = 90U;
constexpr std::uint8_t kDefaultBankConfidence = 85U;
constexpr std::uint8_t kMinimumCodeConfidence = 75U;
constexpr std::uint8_t kIllegalOpcodeConfidence = 60U;
constexpr std::uint8_t kDecodeFailureConfidence = 50U;
constexpr std::uint8_t kPossibleDataConfidence = 60U;
constexpr std::size_t kHeaderDataBegin = 0x0104U;
constexpr std::size_t kHeaderDataEnd = 0x0150U;
constexpr std::size_t kMinimumFillRun = 32U;

struct BankLocation {
    std::uint16_t bank{};
    bool assumes_default_bank{};
};

bool is_header_data(const std::size_t rom_offset) noexcept {
    return rom_offset >= kHeaderDataBegin && rom_offset < kHeaderDataEnd;
}

std::uint8_t evidence_priority(const AnalysisEvidence evidence) noexcept {
    switch (evidence) {
        case AnalysisEvidence::ResetEntry: return 5U;
        case AnalysisEvidence::InterruptVector: return 4U;
        case AnalysisEvidence::DirectBranch:
        case AnalysisEvidence::DirectCall: return 3U;
        case AnalysisEvidence::Fallthrough: return 2U;
        default: return 1U;
    }
}

std::optional<std::size_t> offset_for_address(const rom::Rom& image,
                                              const std::uint16_t bank_index,
                                              const std::uint16_t address) {
    const auto bank = image.bank(bank_index);
    if (!bank.has_value()) {
        return std::nullopt;
    }
    return bank->file_offset_for_cpu_address(address);
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

template <typename Emit>
bool emit_unknown_segments(const rom::RomBank& bank, const std::size_t begin,
                           const std::size_t end, const std::stop_token stop_token,
                           Emit&& emit) {
    const std::span<const std::uint8_t> bytes = bank.bytes();
    std::size_t cursor = begin;
    std::size_t unknown_begin = begin;
    const auto flush_unknown = [&](const std::size_t limit) {
        if (unknown_begin >= limit) {
            return true;
        }
        ClassificationRecord record;
        record.bank = bank.index();
        record.cpu_address = static_cast<std::uint16_t>(
            (bank.index() == 0U ? 0x0000U : 0x4000U) +
            static_cast<std::uint32_t>(unknown_begin));
        record.rom_offset = bank.file_offset() + unknown_begin;
        record.length = limit - unknown_begin;
        record.classification = RegionClassification::Unknown;
        record.evidence = AnalysisEvidence::Unreached;
        return emit(record);
    };

    while (cursor < end) {
        if (stop_token.stop_requested()) {
            return false;
        }
        const std::uint8_t value = bytes[cursor];
        if (value != 0x00U && value != 0xFFU) {
            ++cursor;
            continue;
        }
        std::size_t run_end = cursor + 1U;
        while (run_end < end && bytes[run_end] == value) {
            if (stop_token.stop_requested()) {
                return false;
            }
            ++run_end;
        }
        if (run_end - cursor < kMinimumFillRun) {
            cursor = run_end;
            continue;
        }
        if (!flush_unknown(cursor)) {
            return false;
        }
        ClassificationRecord record;
        record.bank = bank.index();
        record.cpu_address = static_cast<std::uint16_t>(
            (bank.index() == 0U ? 0x0000U : 0x4000U) +
            static_cast<std::uint32_t>(cursor));
        record.rom_offset = bank.file_offset() + cursor;
        record.length = run_end - cursor;
        record.classification = RegionClassification::PossibleData;
        record.confidence_percent = kPossibleDataConfidence;
        record.evidence = AnalysisEvidence::RepeatedFillBytes;
        if (!emit(record)) {
            return false;
        }
        cursor = run_end;
        unknown_begin = cursor;
    }
    return flush_unknown(end);
}

}  // namespace

ReachabilityStats analyze_reachable_code(const rom::Rom& image,
                                        const ClassificationSink& sink,
                                        const std::stop_token stop_token) {
    ReachabilityStats stats;
    const std::size_t image_size = image.actual_size_bytes();
    if (image_size == 0U) {
        return stats;
    }

    // Values are confidence percentages for reachable instruction starts.
    // A separate compact evidence array keeps memory bounded for large ROMs.
    std::vector<std::uint8_t> start_confidence(image_size, 0U);
    std::vector<AnalysisEvidence> start_evidence(image_size,
                                                  AnalysisEvidence::Unreached);
    std::deque<std::uint64_t> pending;

    const auto offer = [&](const std::uint16_t bank, const std::uint16_t address,
                           const std::uint8_t confidence,
                           const AnalysisEvidence evidence) {
        const auto offset = offset_for_address(image, bank, address);
        if (!offset.has_value() || *offset >= image_size || is_header_data(*offset)) {
            return;
        }
        std::uint8_t& best = start_confidence[*offset];
        if (confidence > best) {
            best = confidence;
            start_evidence[*offset] = evidence;
            const std::uint64_t packed =
                (static_cast<std::uint64_t>(confidence) << 32U) |
                static_cast<std::uint32_t>(*offset);
            pending.push_back(packed);
        } else if (confidence == best &&
                   evidence_priority(evidence) > evidence_priority(start_evidence[*offset])) {
            start_evidence[*offset] = evidence;
        }
    };

    offer(0U, 0x0100U, kResetConfidence, AnalysisEvidence::ResetEntry);
    constexpr std::uint16_t kInterruptVectors[]{0x0040U, 0x0048U, 0x0050U,
                                                0x0058U, 0x0060U};
    for (const std::uint16_t vector : kInterruptVectors) {
        offer(0U, vector, kInterruptConfidence, AnalysisEvidence::InterruptVector);
    }

    while (!pending.empty()) {
        if (stop_token.stop_requested()) {
            stats.cancelled = true;
            return stats;
        }
        const std::uint64_t packed = pending.front();
        pending.pop_front();
        const std::size_t rom_offset = static_cast<std::uint32_t>(packed & 0xFFFFFFFFU);
        const std::uint8_t current_confidence = static_cast<std::uint8_t>(packed >> 32U);
        if (rom_offset >= start_confidence.size() ||
            current_confidence != start_confidence[rom_offset]) {
            continue;
        }
        const std::size_t bank_index = rom_offset / rom::kRomBankSize;
        const auto bank = image.bank(static_cast<std::uint16_t>(bank_index));
        if (!bank.has_value() || rom_offset < bank->file_offset()) {
            continue;
        }
        const std::size_t local_offset = rom_offset - bank->file_offset();
        const std::span<const std::uint8_t> bank_bytes = bank->bytes();
        if (local_offset >= bank_bytes.size()) {
            continue;
        }
        const std::uint32_t base = bank_index == 0U ? 0x0000U : 0x4000U;
        const auto address = static_cast<std::uint16_t>(base +
            static_cast<std::uint32_t>(local_offset));
        const cpu::DecodeResult decoded = cpu::decode_sm83_instruction(
            bank_bytes.subspan(local_offset), address);
        if (!decoded.success()) {
            continue;
        }
        const cpu::Instruction& instruction = *decoded.instruction;
        const std::uint32_t next_address = static_cast<std::uint32_t>(address) +
                                           instruction.length;

        const auto offer_fallthrough = [&]() {
            const std::uint16_t source_bank = static_cast<std::uint16_t>(bank_index);
            const auto location = bank_for_fallthrough(image, source_bank, next_address);
            if (!location.has_value()) {
                return;
            }
            const std::uint8_t next_confidence = location->assumes_default_bank
                ? std::min(current_confidence, kDefaultBankConfidence)
                : std::min(current_confidence, kFallthroughConfidence);
            offer(location->bank, static_cast<std::uint16_t>(next_address), next_confidence,
                  AnalysisEvidence::Fallthrough);
        };

        const auto offer_direct_target = [&](const AnalysisEvidence evidence) {
            if (!instruction.branch_target.has_value()) {
                return;
            }
            const std::uint16_t source_bank = static_cast<std::uint16_t>(bank_index);
            const auto location = bank_for_target(image, source_bank,
                                                   *instruction.branch_target);
            if (!location.has_value()) {
                return;
            }
            const std::uint8_t edge_confidence = location->assumes_default_bank
                ? kDefaultBankConfidence
                : kDirectEdgeConfidence;
            offer(location->bank, *instruction.branch_target,
                  std::min(current_confidence, edge_confidence), evidence);
        };

        switch (instruction.control_flow) {
            case cpu::ControlFlowType::Sequential:
                offer_fallthrough();
                break;
            case cpu::ControlFlowType::ConditionalBranch:
                offer_direct_target(AnalysisEvidence::DirectBranch);
                offer_fallthrough();
                break;
            case cpu::ControlFlowType::UnconditionalBranch:
                offer_direct_target(AnalysisEvidence::DirectBranch);
                break;
            case cpu::ControlFlowType::Call:
            case cpu::ControlFlowType::ConditionalCall:
            case cpu::ControlFlowType::Reset:
                offer_direct_target(AnalysisEvidence::DirectCall);
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

    const auto emit = [&](ClassificationRecord record) {
        ++stats.records;
        if (record.classification == RegionClassification::Code) {
            ++stats.code_instructions;
        } else if (record.classification == RegionClassification::PossibleCode) {
            ++stats.possible_code_instructions;
        } else if (record.classification == RegionClassification::Data) {
            ++stats.data_regions;
        } else if (record.classification == RegionClassification::PossibleData) {
            ++stats.possible_data_regions;
        } else if (record.classification == RegionClassification::Unknown) {
            ++stats.unknown_regions;
        }
        if (sink && !sink(record)) {
            stats.stopped_early = true;
            return false;
        }
        return true;
    };

    for (std::size_t bank_index = 0U; bank_index < image.actual_bank_count(); ++bank_index) {
        const auto bank = image.bank(static_cast<std::uint16_t>(bank_index));
        if (!bank.has_value()) {
            continue;
        }
        const std::span<const std::uint8_t> bank_bytes = bank->bytes();
        std::size_t local_offset = 0U;
        std::size_t covered_until = 0U;
        while (local_offset < bank_bytes.size()) {
            if (stop_token.stop_requested()) {
                stats.cancelled = true;
                return stats;
            }
            const std::size_t rom_offset = bank->file_offset() + local_offset;
            if (start_confidence[rom_offset] != 0U) {
                const std::uint32_t base = bank_index == 0U ? 0x0000U : 0x4000U;
                const auto cpu_address = static_cast<std::uint16_t>(
                    base + static_cast<std::uint32_t>(local_offset));
                const cpu::DecodeResult decoded = cpu::decode_sm83_instruction(
                    bank_bytes.subspan(local_offset), cpu_address);
                ClassificationRecord record;
                record.bank = static_cast<std::uint16_t>(bank_index);
                record.cpu_address = cpu_address;
                record.rom_offset = rom_offset;
                const bool overlaps_instruction = local_offset < covered_until;
                if (!decoded.success()) {
                    record.length = 1U;
                    record.classification = RegionClassification::PossibleCode;
                    record.confidence_percent = std::min(start_confidence[rom_offset],
                                                         kDecodeFailureConfidence);
                    record.evidence = AnalysisEvidence::TruncatedInstruction;
                    record.raw_byte = bank_bytes[local_offset];
                    ++stats.decode_failures;
                } else {
                    record.length = decoded.instruction->length;
                    record.instruction = decoded.instruction;
                    ++stats.reachable_instructions;
                    const std::uint8_t confidence = start_confidence[rom_offset];
                    if (overlaps_instruction) {
                        record.classification = RegionClassification::PossibleCode;
                        record.confidence_percent = std::min(confidence, kDecodeFailureConfidence);
                        record.evidence = AnalysisEvidence::InstructionOverlap;
                    } else if (!decoded.instruction->legal) {
                        record.classification = RegionClassification::PossibleCode;
                        record.confidence_percent = std::min(confidence, kIllegalOpcodeConfidence);
                        record.evidence = AnalysisEvidence::UndocumentedOpcode;
                    } else if (confidence >= kMinimumCodeConfidence) {
                        record.classification = RegionClassification::Code;
                        record.confidence_percent = confidence;
                        record.evidence = start_evidence[rom_offset];
                    } else {
                        record.classification = RegionClassification::PossibleCode;
                        record.confidence_percent = confidence;
                        record.evidence = start_evidence[rom_offset];
                    }
                    covered_until = std::max(covered_until,
                                             local_offset + record.length);
                }
                if (!emit(std::move(record))) {
                    return stats;
                }
                ++local_offset;
                continue;
            }

            if (local_offset < covered_until) {
                ++local_offset;
                continue;
            }

            if (is_header_data(rom_offset)) {
                std::size_t end = local_offset + 1U;
                while (end < bank_bytes.size() &&
                       is_header_data(bank->file_offset() + end) &&
                       start_confidence[bank->file_offset() + end] == 0U) {
                    if (stop_token.stop_requested()) {
                        stats.cancelled = true;
                        return stats;
                    }
                    ++end;
                }
                ClassificationRecord record;
                record.bank = static_cast<std::uint16_t>(bank_index);
                record.cpu_address = static_cast<std::uint16_t>(0x0000U +
                    static_cast<std::uint32_t>(local_offset));
                record.rom_offset = rom_offset;
                record.length = end - local_offset;
                record.classification = RegionClassification::Data;
                record.confidence_percent = 99U;
                record.evidence = AnalysisEvidence::CartridgeHeader;
                if (!emit(std::move(record))) {
                    return stats;
                }
                local_offset = end;
                continue;
            }

            std::size_t end = local_offset + 1U;
            while (end < bank_bytes.size() && end >= covered_until &&
                   start_confidence[bank->file_offset() + end] == 0U &&
                   !is_header_data(bank->file_offset() + end)) {
                if (stop_token.stop_requested()) {
                    stats.cancelled = true;
                    return stats;
                }
                ++end;
            }
            if (!emit_unknown_segments(*bank, local_offset, end, stop_token,
                                       [&](const ClassificationRecord& record) {
                                           return emit(record);
                                       })) {
                stats.cancelled = stop_token.stop_requested();
                return stats;
            }
            local_offset = end;
        }
    }
    return stats;
}

std::string_view classification_name(const RegionClassification classification) noexcept {
    switch (classification) {
        case RegionClassification::Code: return "CODE";
        case RegionClassification::Data: return "DATA";
        case RegionClassification::Unknown: return "UNKNOWN";
        case RegionClassification::PossibleCode: return "POSSIBLE_CODE";
        case RegionClassification::PossibleData: return "POSSIBLE_DATA";
        case RegionClassification::JumpTable: return "JUMP_TABLE";
        case RegionClassification::PointerTable: return "POINTER_TABLE";
        case RegionClassification::Graphics: return "GRAPHICS";
        case RegionClassification::Text: return "TEXT";
        case RegionClassification::Audio: return "AUDIO";
        case RegionClassification::CompressedData: return "COMPRESSED_DATA";
    }
    return "UNKNOWN";
}

std::string_view evidence_name(const AnalysisEvidence evidence) noexcept {
    switch (evidence) {
        case AnalysisEvidence::ResetEntry: return "reset entry";
        case AnalysisEvidence::InterruptVector: return "interrupt vector";
        case AnalysisEvidence::DirectBranch: return "direct branch target";
        case AnalysisEvidence::DirectCall: return "direct call target";
        case AnalysisEvidence::Fallthrough: return "fall-through";
        case AnalysisEvidence::CartridgeHeader: return "cartridge header";
        case AnalysisEvidence::UndocumentedOpcode: return "undocumented opcode";
        case AnalysisEvidence::TruncatedInstruction: return "incomplete instruction";
        case AnalysisEvidence::InstructionOverlap: return "overlapping instruction boundary";
        case AnalysisEvidence::RepeatedFillBytes: return "repeated 00/FF fill bytes";
        case AnalysisEvidence::Unreached: return "not reached from configured entry points";
    }
    return "unknown evidence";
}

}  // namespace tool::analysis
