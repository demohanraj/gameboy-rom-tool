#include "tool/disasm/Disassembler.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stop_token>
#include <string>
#include <utility>

namespace tool::disasm {
namespace {

std::string hex_value(const std::uint32_t value, const int digits) {
    std::ostringstream output;
    output << '$' << std::uppercase << std::hex << std::setfill('0')
           << std::setw(digits) << value;
    return output.str();
}

DisassemblyEntry make_raw_byte(const std::uint16_t bank, const std::uint16_t cpu_address,
                               const std::size_t rom_offset, const std::uint8_t value,
                               const cpu::DecodeErrorCode error) {
    DisassemblyEntry entry;
    entry.bank = bank;
    entry.cpu_address = cpu_address;
    entry.rom_offset = rom_offset;
    entry.raw_byte = value;
    entry.decode_error = error;
    return entry;
}

}  // namespace

DisassemblyStats disassemble_rom(const rom::Rom& image, const DisassemblySink& sink,
                                const std::stop_token stop_token) {
    DisassemblyStats stats;
    for (std::size_t bank_index = 0; bank_index < image.actual_bank_count(); ++bank_index) {
        const auto bank = image.bank(static_cast<std::uint16_t>(bank_index));
        if (!bank.has_value()) {
            continue;
        }
        const std::span<const std::uint8_t> bank_bytes = bank->bytes();
        std::size_t local_offset = 0;
        while (local_offset < bank_bytes.size()) {
            if (stop_token.stop_requested()) {
                stats.cancelled = true;
                return stats;
            }
            const std::uint32_t base_address = bank_index == 0U ? 0x0000U : 0x4000U;
            const auto cpu_address = static_cast<std::uint16_t>(base_address +
                static_cast<std::uint32_t>(local_offset));
            const std::span<const std::uint8_t> remaining = bank_bytes.subspan(local_offset);
            cpu::DecodeResult decoded = cpu::decode_sm83_instruction(remaining, cpu_address);

            DisassemblyEntry entry;
            if (decoded.success()) {
                entry.bank = static_cast<std::uint16_t>(bank_index);
                entry.cpu_address = cpu_address;
                entry.rom_offset = bank->file_offset() + local_offset;
                entry.instruction = std::move(decoded.instruction);
                ++stats.decoded_instructions;
                if (!entry.instruction->legal) {
                    ++stats.illegal_opcodes;
                }
                local_offset += entry.instruction->length;
            } else {
                entry = make_raw_byte(static_cast<std::uint16_t>(bank_index), cpu_address,
                                      bank->file_offset() + local_offset, bank_bytes[local_offset],
                                      decoded.error);
                ++stats.undecoded_bytes;
                ++local_offset;
            }

            ++stats.entries;
            if (sink && !sink(entry)) {
                stats.stopped_early = true;
                return stats;
            }
        }
    }
    return stats;
}

std::string format_disassembly_entry(const DisassemblyEntry& entry) {
    std::ostringstream output;
    output << 'B' << std::uppercase << std::hex << std::setfill('0')
           << std::setw(4) << entry.bank << ":$" << std::setw(4) << entry.cpu_address
           << " [ROM $" << std::setw(6) << entry.rom_offset << "] ";

    const std::span<const std::uint8_t> bytes = entry.instruction.has_value()
        ? std::span<const std::uint8_t>(entry.instruction->bytes)
        : std::span<const std::uint8_t>(&entry.raw_byte, 1U);
    for (std::size_t index = 0; index < 3U; ++index) {
        if (index < bytes.size()) {
            output << std::setw(2) << static_cast<unsigned>(bytes[index]) << ' ';
        } else {
            output << "   ";
        }
    }
    output << ' ';
    if (entry.instruction.has_value()) {
        output << entry.instruction->mnemonic;
        if (!entry.instruction->operands.empty()) {
            output << ' ' << entry.instruction->operands;
        }
        if (!entry.instruction->legal) {
            output << " ; undocumented opcode";
        }
    } else {
        output << ".DB " << hex_value(entry.raw_byte, 2)
               << " ; incomplete instruction at physical bank boundary";
    }
    return output.str();
}

}  // namespace tool::disasm
