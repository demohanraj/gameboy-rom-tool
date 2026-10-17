#include "tool/analysis/MemoryDataAnalyzer.h"

#include "tool/analysis/CodeDataAnalyzer.h"
#include "tool/analysis/CrossReferences.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iterator>
#include <map>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace tool::analysis {
namespace {

bool printable_ascii(const std::uint8_t value) noexcept {
    return value >= 0x20U && value <= 0x7EU;
}

std::uint8_t confidence_for(const RegionClassification classification) noexcept {
    switch (classification) {
        case RegionClassification::Data: return 80U;
        case RegionClassification::PossibleData: return 65U;
        case RegionClassification::Unknown: return 40U;
        default: return 25U;
    }
}

std::string hex_value(const std::uint16_t value, const int digits) {
    std::ostringstream output;
    output << std::uppercase << std::hex << std::setfill('0') << std::setw(digits) << value;
    return output.str();
}

}  // namespace

MemoryDataResult analyze_memory_and_data(const rom::Rom& image,
                                         const std::stop_token stop_token) {
    MemoryDataResult result;
    const CrossReferenceResult references = build_cross_references(image, stop_token);
    if (references.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }

    std::vector<RegionClassification> classification(image.actual_size_bytes(),
                                                       RegionClassification::Unknown);
    std::vector<std::uint8_t> code_bytes(image.actual_size_bytes(), 0U);
    const ReachabilityStats stats = analyze_reachable_code(
        image, [&](const ClassificationRecord& record) {
            const std::size_t end = std::min(image.actual_size_bytes(),
                                             record.rom_offset + record.length);
            for (std::size_t offset = record.rom_offset; offset < end; ++offset) {
                classification[offset] = record.classification;
            }
            if (record.instruction.has_value() &&
                (record.classification == RegionClassification::Code ||
                 record.classification == RegionClassification::PossibleCode)) {
                const std::size_t code_end = std::min(end,
                    record.rom_offset + record.instruction->length);
                for (std::size_t offset = record.rom_offset; offset < code_end; ++offset) {
                    code_bytes[offset] = 1U;
                }
            }
            return true;
        }, stop_token);
    if (stats.cancelled || stop_token.stop_requested()) {
        result.cancelled = true;
        return result;
    }

    std::set<std::tuple<std::uint16_t, std::uint16_t>> direct_seen;
    for (const CrossReference& reference : references.references) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            result.candidates.clear();
            return result;
        }
        if (reference.kind != XrefKind::CodeToData ||
            reference.target.space != XrefAddressSpace::Rom ||
            !reference.target.bank.has_value() ||
            !reference.target.rom_offset.has_value() ||
            !direct_seen.emplace(*reference.target.bank, reference.target.address).second) {
            continue;
        }
        const std::size_t offset = *reference.target.rom_offset;
        if (offset >= image.actual_size_bytes()) {
            continue;
        }
        const auto bank = image.bank(*reference.target.bank);
        if (!bank.has_value()) {
            continue;
        }
        const std::size_t local = offset - bank->file_offset();
        const std::uint8_t value = bank->bytes()[local];
        std::ostringstream preview;
        preview << "byte $" << hex_value(value, 2U);
        result.candidates.push_back({DataCandidateKind::ReferencedRom,
            *reference.target.bank, reference.target.address, offset, 1U,
            reference.confidence_percent, preview.str()});
    }
    result.direct_rom_references = direct_seen.size();

    // Group adjacent aligned pointer candidates. The inferred contents remain
    // tentative because these bytes may be another table or packed data.
    std::map<std::uint16_t, std::map<std::uint16_t, const CrossReference*>> pointer_entries;
    for (const CrossReference& reference : references.references) {
        if (reference.kind == XrefKind::DataToCode && reference.source.bank.has_value() &&
            (reference.source.address & 1U) == 0U) {
            pointer_entries[*reference.source.bank][reference.source.address] = &reference;
        }
    }
    for (const auto& [bank_index, entries] : pointer_entries) {
        auto current = entries.begin();
        while (current != entries.end()) {
            auto end = current;
            std::uint8_t confidence = current->second->confidence_percent;
            while (std::next(end) != entries.end() &&
                   static_cast<std::uint32_t>(std::next(end)->first) ==
                       static_cast<std::uint32_t>(end->first) + 2U) {
                ++end;
                confidence = std::min(confidence, end->second->confidence_percent);
            }
            const std::size_t count = static_cast<std::size_t>(std::distance(current, end)) + 1U;
            if (count >= 2U) {
                const auto bank = image.bank(bank_index);
                if (bank.has_value()) {
                    const std::size_t local = current->first -
                        (bank_index == 0U ? 0U : 0x4000U);
                    const std::size_t offset = bank->file_offset() + local;
                    std::ostringstream preview;
                    preview << count << " pointers:";
                    for (auto entry = current; entry != std::next(end); ++entry) {
                        preview << " $" << hex_value(entry->second->target.address, 4U);
                    }
                    result.candidates.push_back({DataCandidateKind::PointerTable,
                        bank_index, current->first, offset, count * 2U,
                        confidence, preview.str()});
                    ++result.pointer_tables;
                }
            }
            current = std::next(end);
        }
    }

    // Strings are recognized only outside code bytes and remain candidates.
    for (std::size_t bank_index = 0; bank_index < image.actual_bank_count(); ++bank_index) {
        if (stop_token.stop_requested()) {
            result.cancelled = true;
            result.candidates.clear();
            return result;
        }
        const auto bank = image.bank(static_cast<std::uint16_t>(bank_index));
        if (!bank.has_value()) {
            continue;
        }
        const std::span<const std::uint8_t> bytes = bank->bytes();
        const std::uint32_t base = bank_index == 0U ? 0U : 0x4000U;
        std::size_t cursor = 0U;
        while (cursor < bytes.size()) {
            const std::size_t offset = bank->file_offset() + cursor;
            if (code_bytes[offset] != 0U || !printable_ascii(bytes[cursor])) {
                ++cursor;
                continue;
            }
            const std::size_t begin = cursor;
            while (cursor < bytes.size() &&
                   code_bytes[bank->file_offset() + cursor] == 0U &&
                   printable_ascii(bytes[cursor])) {
                ++cursor;
            }
            const std::size_t length = cursor - begin;
            if (length < 4U) {
                continue;
            }
            const std::size_t string_offset = bank->file_offset() + begin;
            std::string preview;
            preview.reserve(std::min<std::size_t>(length, 48U));
            for (std::size_t index = begin;
                 index < std::min(cursor, begin + 48U); ++index) {
                preview.push_back(static_cast<char>(bytes[index]));
            }
            const std::size_t candidate_length = length +
                ((cursor < bytes.size() && bytes[cursor] == 0U) ? 1U : 0U);
            const std::uint16_t address = static_cast<std::uint16_t>(base + begin);
            result.candidates.push_back({DataCandidateKind::Text,
                static_cast<std::uint16_t>(bank_index), address, string_offset,
                candidate_length, confidence_for(classification[string_offset]),
                std::move(preview)});
            ++result.text_strings;
        }
    }

    std::sort(result.candidates.begin(), result.candidates.end(),
        [](const DataCandidate& left, const DataCandidate& right) {
            if (left.bank != right.bank) return left.bank < right.bank;
            if (left.cpu_address != right.cpu_address) return left.cpu_address < right.cpu_address;
            return left.kind < right.kind;
        });
    return result;
}

std::string_view data_candidate_kind_name(const DataCandidateKind kind) noexcept {
    switch (kind) {
        case DataCandidateKind::ReferencedRom: return "REFERENCED_ROM";
        case DataCandidateKind::PointerTable: return "POINTER_TABLE_CANDIDATE";
        case DataCandidateKind::Text: return "TEXT_CANDIDATE";
    }
    return "UNKNOWN";
}

std::string format_data_candidate(const DataCandidate& candidate) {
    std::ostringstream output;
    output << data_candidate_kind_name(candidate.kind) << ' '
           << static_cast<unsigned>(candidate.confidence_percent) << "% B"
           << std::uppercase << std::hex << std::setfill('0') << std::setw(4)
           << candidate.bank << ":$" << std::setw(4) << candidate.cpu_address
           << std::dec << " length=" << candidate.length << " ; " << candidate.preview;
    return output.str();
}

}  // namespace tool::analysis
