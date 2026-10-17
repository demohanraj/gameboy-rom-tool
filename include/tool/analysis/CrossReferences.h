#pragma once

#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace tool::analysis {

enum class XrefKind : std::uint8_t {
    CodeToCode,
    CodeToData,
    DataToCode,
    CodeToRam,
    CodeToHardwareRegister,
    CodeToMapperRegister,
    CodeToUnusable,
    BankToBank,
    FunctionToFunction,
};

enum class XrefAddressSpace : std::uint8_t {
    Rom,
    Ram,
    Hardware,
    Mapper,
    Unusable,
};

struct XrefLocation {
    XrefAddressSpace space{XrefAddressSpace::Rom};
    std::optional<std::uint16_t> bank;
    std::uint16_t address{};
    std::optional<std::size_t> rom_offset;
};

struct CrossReference {
    XrefKind kind{XrefKind::CodeToCode};
    XrefLocation source;
    XrefLocation target;
    std::string source_function_id;
    std::string target_function_id;
    std::string mnemonic;
    std::uint8_t confidence_percent{};
    bool candidate{};
};

struct CrossReferenceResult {
    std::vector<CrossReference> references;
    std::size_t functions_analyzed{};
    std::size_t instructions_analyzed{};
    bool cancelled{};
};

// Builds a bank-aware reference index from reachable instructions and
// conservative little-endian data-pointer candidates. Mapper state is not
// simulated; switch-window references use the project's default-bank rule.
[[nodiscard]] CrossReferenceResult build_cross_references(
    const rom::Rom& image, std::stop_token stop_token = {});

[[nodiscard]] std::string_view xref_kind_name(XrefKind kind) noexcept;
[[nodiscard]] std::string_view xref_address_space_name(XrefAddressSpace space) noexcept;
[[nodiscard]] std::string format_xref_location(const XrefLocation& location);
[[nodiscard]] std::string format_cross_reference(const CrossReference& reference);
[[nodiscard]] std::vector<const CrossReference*> find_references_to(
    const CrossReferenceResult& result, const XrefLocation& target);

}  // namespace tool::analysis
