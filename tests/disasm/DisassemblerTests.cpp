#include "tool/disasm/Disassembler.h"
#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tool::disasm {
namespace {

TEST(DisassemblerTests, PreservesPhysicalBankCpuAddressAndFileOffset) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    bytes[0U] = 0x3EU;
    bytes[1U] = 0x42U;
    bytes[0x4000U] = 0x01U;
    bytes[0x4001U] = 0x01U;
    bytes[0x4002U] = 0x01U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    std::optional<DisassemblyEntry> first_entry;
    std::optional<DisassemblyEntry> second_bank_entry;
    const DisassemblyStats stats = disassemble_rom(*loaded, [&](const DisassemblyEntry& entry) {
        if (entry.rom_offset == 0U) {
            first_entry = entry;
        }
        if (entry.rom_offset == 0x4000U) {
            second_bank_entry = entry;
            return false;
        }
        return true;
    });

    ASSERT_TRUE(first_entry.has_value());
    EXPECT_EQ(first_entry->bank, 0U);
    EXPECT_EQ(first_entry->cpu_address, 0U);
    EXPECT_EQ(first_entry->rom_offset, 0U);
    ASSERT_TRUE(first_entry->instruction.has_value());
    EXPECT_EQ(first_entry->instruction->mnemonic, "LD");
    EXPECT_EQ(first_entry->instruction->operands, "A, $42");

    ASSERT_TRUE(second_bank_entry.has_value());
    EXPECT_EQ(second_bank_entry->bank, 1U);
    EXPECT_EQ(second_bank_entry->cpu_address, 0x4000U);
    EXPECT_EQ(second_bank_entry->rom_offset, 0x4000U);
    ASSERT_TRUE(second_bank_entry->instruction.has_value());
    EXPECT_EQ(second_bank_entry->instruction->operands, "BC, $0101");
    EXPECT_NE(format_disassembly_entry(*second_bank_entry).find("B0001:$4000 [ROM $004000]"),
              std::string::npos);
    EXPECT_TRUE(stats.stopped_early);
}

TEST(DisassemblerTests, AccountsForEveryByteAcrossTheRom) {
    test::TemporaryRomFile file(test::make_test_rom());
    ASSERT_TRUE(file.written());

    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    std::size_t represented_bytes = 0U;
    const DisassemblyStats stats = disassemble_rom(*loaded, [&](const DisassemblyEntry& entry) {
        if (entry.instruction.has_value()) {
            represented_bytes += entry.instruction->length;
        } else {
            ++represented_bytes;
            EXPECT_TRUE(entry.decode_error.has_value());
        }
        return true;
    });

    EXPECT_FALSE(stats.stopped_early);
    EXPECT_EQ(represented_bytes, loaded->actual_size_bytes());
    EXPECT_EQ(stats.entries, stats.decoded_instructions + stats.undecoded_bytes);
}

TEST(DisassemblerTests, EmitsRawByteWhenInstructionIsTruncatedAtRomEnd) {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    bytes.resize(0x152U);
    bytes[0x151U] = 0x01U;
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    std::optional<DisassemblyEntry> trailing_entry;
    const DisassemblyStats stats = disassemble_rom(*loaded, [&](const DisassemblyEntry& entry) {
        if (entry.rom_offset == 0x151U) {
            trailing_entry = entry;
            return false;
        }
        return true;
    });

    ASSERT_TRUE(trailing_entry.has_value());
    EXPECT_EQ(trailing_entry->bank, 0U);
    EXPECT_EQ(trailing_entry->cpu_address, 0x0151U);
    EXPECT_EQ(trailing_entry->raw_byte, 0x01U);
    ASSERT_TRUE(trailing_entry->decode_error.has_value());
    EXPECT_EQ(*trailing_entry->decode_error, cpu::DecodeErrorCode::TruncatedInstruction);
    EXPECT_NE(format_disassembly_entry(*trailing_entry).find(".DB $01"), std::string::npos);
    EXPECT_TRUE(stats.stopped_early);
}

}  // namespace
}  // namespace tool::disasm
