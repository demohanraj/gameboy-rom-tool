#pragma once

#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace tool::analysis {

enum class FunctionStartEvidence : std::uint8_t {
    ResetEntry,
    InterruptVector,
    DirectCall,
};

struct FunctionInfo {
    // The ID encodes the physical bank and CPU address, so it remains unique
    // when a switchable CPU address maps to multiple ROM banks.
    std::string id;
    std::string name;
    std::uint16_t bank{};
    std::uint16_t cpu_address{};
    std::uint8_t confidence_percent{};
    FunctionStartEvidence start_evidence{FunctionStartEvidence::DirectCall};
    std::size_t reachable_instruction_count{};
    std::vector<std::string> callers;
    std::vector<std::string> callees;
};

struct FunctionDiscoveryResult {
    std::vector<FunctionInfo> functions;
    std::size_t analyzed_instructions{};
    bool cancelled{};
};

// Discovers entry points from the cartridge reset entry, interrupt vectors,
// and directly encoded CALL/RST targets. It follows intraprocedural control
// flow to find calls; CFG recovery is a later phase.
[[nodiscard]] FunctionDiscoveryResult discover_functions(
    const rom::Rom& image, std::stop_token stop_token = {});

[[nodiscard]] std::string_view function_start_evidence_name(
    FunctionStartEvidence evidence) noexcept;

}  // namespace tool::analysis
