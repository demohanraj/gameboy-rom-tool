#include "tool/cli/Cli.h"
#include "tool/core/Logger.h"
#include "support/RomFixture.h"

#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <vector>

namespace tool::cli {
namespace {

struct CliResult {
    int status;
    std::string output;
    std::string errors;
};

CliResult invoke(std::vector<std::string> arguments) {
    std::vector<const char*> argv;
    argv.reserve(arguments.size());
    for (const std::string& argument : arguments) {
        argv.push_back(argument.c_str());
    }

    std::ostringstream output;
    std::ostringstream errors;
    core::Logger logger(output, errors);
    const int status = run_cli(static_cast<int>(argv.size()), argv.data(), output, errors, logger);
    return {status, output.str(), errors.str()};
}

}  // namespace

TEST(CliTests, PrintsHelpAndDescribesCurrentAnalysisBoundary) {
    const CliResult result = invoke({"tool", "--help"});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("Usage:"), std::string::npos);
    EXPECT_NE(result.output.find("confidence-rated reachable-code analysis"), std::string::npos);
    EXPECT_NE(result.output.find("classify <rom.gb>"), std::string::npos);
    EXPECT_NE(result.output.find("functions <rom.gb>"), std::string::npos);
    EXPECT_NE(result.output.find("cfg <rom.gb>"), std::string::npos);
    EXPECT_NE(result.output.find("xrefs <rom.gb>"), std::string::npos);
    EXPECT_NE(result.output.find("memory <rom.gb>"), std::string::npos);
    EXPECT_NE(result.output.find("ir <rom.gb>"), std::string::npos);
}

TEST(CliTests, PrintsVersion) {
    const CliResult result = invoke({"tool", "--version"});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("tool 0.1.0"), std::string::npos);
}

TEST(CliTests, RejectsMissingRomArgument) {
    const CliResult result = invoke({"tool", "analyze"});

    EXPECT_EQ(result.status, 2);
    EXPECT_NE(result.errors.find("expects exactly one ROM path"), std::string::npos);
}

TEST(CliTests, AnalyzesRomMetadataForExplicitAndImplicitCommands) {
    test::TemporaryRomFile file(test::make_test_rom(0x01U, 0x00U, 0x00U, "CLI TEST"));
    ASSERT_TRUE(file.written());

    const CliResult explicit_result = invoke({"tool", "analyze", file.path().string()});
    EXPECT_EQ(explicit_result.status, 0);
    EXPECT_NE(explicit_result.output.find("CLI TEST"), std::string::npos);
    EXPECT_NE(explicit_result.output.find("MBC1"), std::string::npos);
    EXPECT_NE(explicit_result.output.find("ROM status: valid"), std::string::npos);

    const CliResult implicit_result = invoke({"tool", file.path().string()});
    EXPECT_EQ(implicit_result.status, 0);
    EXPECT_NE(implicit_result.output.find("ROM metadata"), std::string::npos);
}

TEST(CliTests, ReportsRomLoadFailure) {
    const CliResult result = invoke({"tool", "analyze", "missing-tool-test-rom.gb"});

    EXPECT_EQ(result.status, 1);
    EXPECT_NE(result.errors.find("could not open ROM file"), std::string::npos);
}

TEST(CliTests, DisassemblesRomAndReportsBankAwareAddresses) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "DISASM TEST");
    bytes[0U] = 0x3EU;
    bytes[1U] = 0x42U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "disassemble", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("Mode: linear sweep by physical bank"), std::string::npos);
    EXPECT_NE(result.output.find("B0000:$0000 [ROM $000000]"), std::string::npos);
    EXPECT_NE(result.output.find("LD A, $42"), std::string::npos);
    EXPECT_NE(result.output.find("B0001:$4000 [ROM $004000]"), std::string::npos);
    EXPECT_NE(result.output.find("Disassembly entries:"), std::string::npos);
}

TEST(CliTests, ClassifiesReachableCodeAndKnownHeaderData) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "CLASSIFY TEST");
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "classify", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("ROM code/data classification"), std::string::npos);
    EXPECT_NE(result.output.find("CODE 100% B0000:$0100"), std::string::npos);
    EXPECT_NE(result.output.find("DATA 99% B0000:$0104"), std::string::npos);
    EXPECT_NE(result.output.find("UNKNOWN"), std::string::npos);
    EXPECT_NE(result.output.find("Reachability:"), std::string::npos);
}

TEST(CliTests, DiscoversFunctionEntriesAndDirectCallRelationships) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "FUNCTION TEST");
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $0160
    bytes[0x0151U] = 0x60U;
    bytes[0x0152U] = 0x01U;
    bytes[0x0153U] = 0xC9U;
    bytes[0x0160U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "functions", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("ROM function discovery"), std::string::npos);
    EXPECT_NE(result.output.find("entry_0100"), std::string::npos);
    EXPECT_NE(result.output.find("sub_0160"), std::string::npos);
    EXPECT_NE(result.output.find("fn_b0000_0160"), std::string::npos);
    EXPECT_NE(result.output.find("Functions discovered:"), std::string::npos);
}

TEST(CliTests, EmitsGraphvizDotForControlFlowGraphs) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "CFG TEST");
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0x20U;  // JR NZ, $0154
    bytes[0x0151U] = 0x02U;
    bytes[0x0152U] = 0xC9U;
    bytes[0x0154U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "cfg", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("digraph TOOL_CFG"), std::string::npos);
    EXPECT_NE(result.output.find("conditional_true"), std::string::npos);
    EXPECT_NE(result.output.find("conditional_false"), std::string::npos);
    EXPECT_NE(result.output.find("bb_fn_b0000_0100_b0000_0150"), std::string::npos);
}

TEST(CliTests, PrintsBankAwareCrossReferences) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "XREF TEST");
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;  // JP $0150
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xCDU;  // CALL $0160
    bytes[0x0151U] = 0x60U;
    bytes[0x0152U] = 0x01U;
    bytes[0x0153U] = 0xC9U;
    bytes[0x0160U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "xrefs", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("ROM cross references"), std::string::npos);
    EXPECT_NE(result.output.find("code->code"), std::string::npos);
    EXPECT_NE(result.output.find("function->function"), std::string::npos);
    EXPECT_NE(result.output.find("Cross references:"), std::string::npos);
}

TEST(CliTests, ReportsMemoryMapRegistersAndDataCandidates) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "MEMORY TEST");
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0xFAU;  // LD A, [$0200]
    bytes[0x0151U] = 0x00U;
    bytes[0x0152U] = 0x02U;
    bytes[0x0153U] = 0xC9U;
    bytes[0x0200U] = 'H';
    bytes[0x0201U] = 'E';
    bytes[0x0202U] = 'L';
    bytes[0x0203U] = 'L';
    bytes[0x0204U] = 'O';
    bytes[0x0205U] = 0U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "memory", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("Game Boy memory map and data analysis"), std::string::npos);
    EXPECT_NE(result.output.find("$FF00-$FF7F  I/O registers"), std::string::npos);
    EXPECT_NE(result.output.find("DIV"), std::string::npos);
    EXPECT_NE(result.output.find("REFERENCED_ROM"), std::string::npos);
    EXPECT_NE(result.output.find("TEXT_CANDIDATE"), std::string::npos);
}

TEST(CliTests, EmitsStructuredOpcodeLevelIr) {
    std::vector<std::uint8_t> bytes = test::make_test_rom(0x01U, 0x00U, 0x00U, "IR TEST");
    for (const std::size_t vector : {0x0040U, 0x0048U, 0x0050U, 0x0058U, 0x0060U}) {
        bytes[vector] = 0xC9U;
    }
    bytes[0x0100U] = 0xC3U;
    bytes[0x0101U] = 0x50U;
    bytes[0x0102U] = 0x01U;
    bytes[0x0150U] = 0x3EU;
    bytes[0x0151U] = 0x42U;
    bytes[0x0152U] = 0xC9U;
    test::update_fixture_checksums(bytes);
    test::TemporaryRomFile file(bytes);
    ASSERT_TRUE(file.written());

    const CliResult result = invoke({"tool", "ir", file.path().string()});

    EXPECT_EQ(result.status, 0);
    EXPECT_NE(result.output.find("opcode-level IR"), std::string::npos);
    EXPECT_NE(result.output.find("B0000:$0150 @ROM$000150"), std::string::npos);
    EXPECT_NE(result.output.find("machine-opcode=BASE:3E"), std::string::npos);
    EXPECT_NE(result.output.find("CPU semantic lifting is Phase 10"), std::string::npos);
}

TEST(CliTests, RejectsUnknownCommand) {
    const CliResult result = invoke({"tool", "frobnicate"});

    EXPECT_EQ(result.status, 2);
    EXPECT_NE(result.errors.find("unknown command"), std::string::npos);
}

}  // namespace tool::cli
