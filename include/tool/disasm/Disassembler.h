#pragma once

#include "tool/cpu/SM83.h"
#include "tool/rom/Rom.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>

namespace tool::disasm {

struct DisassemblyEntry {
    std::uint16_t bank{};
    std::uint16_t cpu_address{};
    std::size_t rom_offset{};
    std::optional<cpu::Instruction> instruction;
    std::uint8_t raw_byte{};
    std::optional<cpu::DecodeErrorCode> decode_error;
};

struct DisassemblyStats {
    std::size_t entries{};
    std::size_t decoded_instructions{};
    std::size_t illegal_opcodes{};
    std::size_t undecoded_bytes{};
    bool stopped_early{};
    bool cancelled{};
};

// The callback receives one entry at a time so large ROMs can be disassembled
// without retaining a second, expanded copy of the whole image in memory.
using DisassemblySink = std::function<bool(const DisassemblyEntry&)>;

[[nodiscard]] DisassemblyStats disassemble_rom(
    const rom::Rom& image, const DisassemblySink& sink,
    std::stop_token stop_token = {});
[[nodiscard]] std::string format_disassembly_entry(const DisassemblyEntry& entry);

}  // namespace tool::disasm
