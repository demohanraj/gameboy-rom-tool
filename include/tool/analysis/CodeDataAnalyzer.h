#pragma once

#include "tool/cpu/Instruction.h"
#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stop_token>
#include <string_view>

namespace tool::analysis {

enum class RegionClassification : std::uint8_t {
    Code,
    Data,
    Unknown,
    PossibleCode,
    PossibleData,
    JumpTable,
    PointerTable,
    Graphics,
    Text,
    Audio,
    CompressedData,
};

enum class AnalysisEvidence : std::uint8_t {
    ResetEntry,
    InterruptVector,
    DirectBranch,
    DirectCall,
    Fallthrough,
    CartridgeHeader,
    UndocumentedOpcode,
    TruncatedInstruction,
    InstructionOverlap,
    RepeatedFillBytes,
    Unreached,
};

struct ClassificationRecord {
    std::uint16_t bank{};
    std::uint16_t cpu_address{};
    std::size_t rom_offset{};
    std::size_t length{};
    RegionClassification classification{RegionClassification::Unknown};
    std::uint8_t confidence_percent{};
    AnalysisEvidence evidence{AnalysisEvidence::Unreached};
    std::optional<cpu::Instruction> instruction;
    std::optional<std::uint8_t> raw_byte;
};

struct ReachabilityStats {
    std::size_t records{};
    std::size_t reachable_instructions{};
    std::size_t code_instructions{};
    std::size_t possible_code_instructions{};
    std::size_t decode_failures{};
    std::size_t data_regions{};
    std::size_t possible_data_regions{};
    std::size_t unknown_regions{};
    bool stopped_early{};
    bool cancelled{};
};

using ClassificationSink = std::function<bool(const ClassificationRecord&)>;

// Seeds the cartridge entry point at $0100 and the five fixed interrupt
// vectors. MBC register state is unknown; switch-window edges use a conservative
// physical-bank assumption described in docs/code-analysis.md.
[[nodiscard]] ReachabilityStats analyze_reachable_code(
    const rom::Rom& image, const ClassificationSink& sink,
    std::stop_token stop_token = {});

[[nodiscard]] std::string_view classification_name(
    RegionClassification classification) noexcept;
[[nodiscard]] std::string_view evidence_name(AnalysisEvidence evidence) noexcept;

}  // namespace tool::analysis
