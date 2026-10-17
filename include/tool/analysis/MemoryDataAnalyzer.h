#pragma once

#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace tool::analysis {

enum class DataCandidateKind : std::uint8_t {
    ReferencedRom,
    PointerTable,
    Text,
};

struct DataCandidate {
    DataCandidateKind kind{DataCandidateKind::ReferencedRom};
    std::uint16_t bank{};
    std::uint16_t cpu_address{};
    std::size_t rom_offset{};
    std::size_t length{};
    std::uint8_t confidence_percent{};
    std::string preview;
};

struct MemoryDataResult {
    std::vector<DataCandidate> candidates;
    std::size_t direct_rom_references{};
    std::size_t pointer_tables{};
    std::size_t text_strings{};
    bool cancelled{};
};

// Reports directly referenced ROM locations, contiguous pointer-table
// candidates, and printable ASCII strings without reclassifying uncertain
// bytes as confirmed data.
[[nodiscard]] MemoryDataResult analyze_memory_and_data(
    const rom::Rom& image, std::stop_token stop_token = {});

[[nodiscard]] std::string_view data_candidate_kind_name(DataCandidateKind kind) noexcept;
[[nodiscard]] std::string format_data_candidate(const DataCandidate& candidate);

}  // namespace tool::analysis
