#include "tool/analysis/MemoryDataAnalyzer.h"

#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace tool::analysis {
namespace {

std::vector<std::uint8_t> make_memory_data_fixture() {
    std::vector<std::uint8_t> bytes = test::make_test_rom();
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $0160
    bytes[0x0151U] = 0x60U;
    bytes[0x0152U] = 0x01U;
    bytes[0x0153U] = 0xFAU;  // LD A, [$0200]
    bytes[0x0154U] = 0x00U;
    bytes[0x0155U] = 0x02U;
    bytes[0x0156U] = 0xC9U;
    bytes[0x0160U] = 0xC9U;
    bytes[0x0200U] = 'H';
    bytes[0x0201U] = 'E';
    bytes[0x0202U] = 'L';
    bytes[0x0203U] = 'L';
    bytes[0x0204U] = 'O';
    bytes[0x0205U] = 0U;
    bytes[0x0300U] = 0x50U;  // Two little-endian code pointers.
    bytes[0x0301U] = 0x01U;
    bytes[0x0302U] = 0x60U;
    bytes[0x0303U] = 0x01U;
    test::update_fixture_checksums(bytes);
    return bytes;
}

TEST(MemoryDataAnalyzerTests, FindsReferencedRomPointerTableAndTextCandidates) {
    test::TemporaryRomFile file(make_memory_data_fixture());
    ASSERT_TRUE(file.written());
    rom::RomLoadError load_error;
    const auto loaded = rom::Rom::load_file(file.path(), load_error);
    ASSERT_TRUE(loaded.has_value()) << load_error.message;

    const MemoryDataResult result = analyze_memory_and_data(*loaded);

    ASSERT_FALSE(result.cancelled);
    EXPECT_GT(result.direct_rom_references, 0U);
    EXPECT_GT(result.pointer_tables, 0U);
    EXPECT_GT(result.text_strings, 0U);
    const auto referenced = std::find_if(result.candidates.begin(), result.candidates.end(),
        [](const DataCandidate& candidate) {
            return candidate.kind == DataCandidateKind::ReferencedRom &&
                   candidate.bank == 0U && candidate.cpu_address == 0x0200U;
        });
    ASSERT_NE(referenced, result.candidates.end());

    const auto pointers = std::find_if(result.candidates.begin(), result.candidates.end(),
        [](const DataCandidate& candidate) {
            return candidate.kind == DataCandidateKind::PointerTable &&
                   candidate.bank == 0U && candidate.cpu_address == 0x0300U;
        });
    ASSERT_NE(pointers, result.candidates.end());
    EXPECT_EQ(pointers->length, 4U);
    EXPECT_NE(pointers->preview.find("$0150"), std::string::npos);
    EXPECT_NE(pointers->preview.find("$0160"), std::string::npos);

    const auto text = std::find_if(result.candidates.begin(), result.candidates.end(),
        [](const DataCandidate& candidate) {
            return candidate.kind == DataCandidateKind::Text &&
                   candidate.bank == 0U && candidate.cpu_address == 0x0200U;
        });
    ASSERT_NE(text, result.candidates.end());
    EXPECT_EQ(text->preview, "HELLO");
}

}  // namespace
}  // namespace tool::analysis
