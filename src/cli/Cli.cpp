#include "tool/cli/Cli.h"

#include "tool/analysis/CodeDataAnalyzer.h"
#include "tool/analysis/ControlFlowGraph.h"
#include "tool/analysis/CrossReferences.h"
#include "tool/analysis/FunctionDiscovery.h"
#include "tool/analysis/MemoryDataAnalyzer.h"
#include "tool/core/Logger.h"
#include "tool/disasm/Disassembler.h"
#include "tool/rom/Rom.h"
#include "tool/memory/MemoryMap.h"
#include "tool/ir/IR.h"
#include "tool/version.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace tool::cli {
namespace {

constexpr int kSuccess = 0;
constexpr int kInvalidArguments = 2;
constexpr int kAnalysisFailed = 1;

void print_usage(std::ostream& output) {
    output << "TOOL Game Boy Reverse-Engineering Tool " << TOOL_VERSION_STRING << "\n"
           << "Usage:\n"
           << "  tool [--help] [--version]\n"
           << "  tool <command> [arguments]\n"
           << "  tool <rom.gb>                  (equivalent to: tool analyze <rom.gb>)\n\n"
           << "Commands:\n"
           << "  analyze <rom.gb>               Analyze a Game Boy ROM\n"
           << "  disassemble <rom.gb>           Disassemble a Game Boy ROM\n"
           << "  classify <rom.gb>              Find reachable code and classify ROM regions\n"
           << "  functions <rom.gb>             Discover function entries and call relationships\n"
           << "  cfg <rom.gb>                   Emit Graphviz DOT control-flow graphs\n"
           << "  xrefs <rom.gb>                 Build a bank-aware cross-reference index\n"
           << "  memory <rom.gb>                Report the memory map and data candidates\n"
           << "  ir <rom.gb>                     Emit the structured opcode-level IR\n"
           << "  decompile <rom.gb> --output DIR\n"
           << "                                 Reconstruct C into DIR\n\n"
           << "Phase 4 adds confidence-rated reachable-code analysis; Phases 5-8 add functions, CFGs, cross references, and memory/data analysis.\n"
           << "Phase 9 adds structured opcode-level IR; CPU semantic lifting is a later phase.\n"
           << "The linear disassembly still includes candidate instructions; mapper state is not modeled.\n"
           << "Reconstructed output is intended to be an approximation, not a recovery of the original source code.\n";
}

bool has_rom_extension(const std::string_view value) {
    const std::filesystem::path path{std::string(value)};
    std::string extension = path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return extension == ".gb" || extension == ".gbc";
}

int report_unavailable(const std::string_view command, core::Logger& logger) {
    logger.log(core::LogLevel::Warning,
               "The '" + std::string(command) + "' pipeline is not implemented in this build.");
    return kCommandUnavailable;
}

std::string format_kibibytes(const std::uint32_t bytes) {
    if (bytes % 1024U == 0U) {
        return std::to_string(bytes / 1024U) + " KiB";
    }
    return std::to_string(bytes) + " bytes";
}

int analyze_rom(const std::string_view rom_path, std::ostream& output,
                std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    const rom::RomHeader& header = image.header();
    constexpr char hex_digits[] = "0123456789ABCDEF";
    output << "ROM metadata\n"
           << "  File: " << image.path().string() << '\n'
           << "  Title: " << (header.title.empty() ? "(untitled)" : header.title) << '\n'
           << "  Cartridge: " << header.cartridge.type_name << " (0x"
           << hex_digits[header.cartridge.type_code >> 4U]
           << hex_digits[header.cartridge.type_code & 0x0FU] << ")\n"
           << "  Mapper: " << rom::mapper_name(header.cartridge.mapper) << '\n'
           << "  ROM size: declared " << format_kibibytes(header.declared_rom_size_bytes)
           << " in " << header.declared_rom_bank_count << " banks; actual "
           << format_kibibytes(static_cast<std::uint32_t>(image.actual_size_bytes()))
           << " in " << image.actual_bank_count() << " banks\n"
           << "  RAM size: ";
    if (!header.ram_size_known) {
        output << "unknown (header code 0x" << hex_digits[header.ram_size_code >> 4U]
               << hex_digits[header.ram_size_code & 0x0FU] << ")\n";
    } else {
        output << format_kibibytes(header.declared_ram_size_bytes) << '\n';
    }
    output << "  Nintendo logo: " << (header.nintendo_logo_valid ? "valid" : "invalid") << '\n'
           << "  Header checksum: " << (header.header_checksum_valid ? "valid" : "invalid") << '\n'
           << "  Global checksum: " << (header.global_checksum_valid ? "valid" : "invalid") << '\n'
           << "  ROM status: " << (image.is_valid() ? "valid" : "invalid") << '\n';

    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }
    return image.is_valid() ? kSuccess : kAnalysisFailed;
}

int disassemble_rom_file(const std::string_view rom_path, std::ostream& output,
                         std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    output << "ROM disassembly\n"
           << "  File: " << image.path().string() << '\n'
           << "  Mode: linear sweep by physical bank; code/data is unclassified\n";
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }

    const disasm::DisassemblyStats stats = disasm::disassemble_rom(
        image, [&output](const disasm::DisassemblyEntry& entry) {
            output << disasm::format_disassembly_entry(entry) << '\n';
            return static_cast<bool>(output);
        });
    output << "Disassembly entries: " << stats.entries
           << " (decoded: " << stats.decoded_instructions
           << ", undocumented opcodes: " << stats.illegal_opcodes
           << ", incomplete bytes: " << stats.undecoded_bytes << ")\n";
    return image.is_valid() && !stats.stopped_early ? kSuccess : kAnalysisFailed;
}

std::string format_classification_record(const analysis::ClassificationRecord& record) {
    std::ostringstream line;
    line << analysis::classification_name(record.classification) << ' ';
    if (record.confidence_percent != 0U) {
        line << static_cast<unsigned>(record.confidence_percent) << "% ";
    } else {
        line << "--% ";
    }

    if (record.instruction.has_value() || record.raw_byte.has_value()) {
        disasm::DisassemblyEntry entry;
        entry.bank = record.bank;
        entry.cpu_address = record.cpu_address;
        entry.rom_offset = record.rom_offset;
        entry.instruction = record.instruction;
        if (record.raw_byte.has_value()) {
            entry.raw_byte = *record.raw_byte;
        }
        line << disasm::format_disassembly_entry(entry);
    } else {
        line << 'B' << std::uppercase << std::hex << std::setfill('0')
             << std::setw(4) << record.bank << ":$" << std::setw(4)
             << record.cpu_address << " [ROM $" << std::setw(6)
             << record.rom_offset << "] length=0x" << record.length;
    }
    line << " ; evidence: " << analysis::evidence_name(record.evidence);
    return line.str();
}

int classify_rom_file(const std::string_view rom_path, std::ostream& output,
                      std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    output << "ROM code/data classification\n"
           << "  File: " << image.path().string() << '\n'
           << "  Entry points: cartridge entry $0100 and interrupt vectors $0040, $0048, $0050, $0058, $0060\n"
           << "  Mapper state: not modeled; switchable-window edges use a physical-bank assumption\n";
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }

    const analysis::ReachabilityStats stats = analysis::analyze_reachable_code(
        image, [&output](const analysis::ClassificationRecord& record) {
            output << format_classification_record(record) << '\n';
            return static_cast<bool>(output);
        });
    output << "Reachability: " << stats.reachable_instructions << " decoded instructions ("
           << stats.code_instructions << " CODE, " << stats.possible_code_instructions
           << " POSSIBLE_CODE, " << stats.decode_failures << " decode failures); regions: "
           << stats.data_regions << " DATA, " << stats.possible_data_regions
           << " POSSIBLE_DATA, " << stats.unknown_regions << " UNKNOWN\n";
    return image.is_valid() && !stats.stopped_early ? kSuccess : kAnalysisFailed;
}

void print_function_ids(std::ostream& output, const char* label,
                        const std::vector<std::string>& ids) {
    output << "  " << label << ":";
    if (ids.empty()) {
        output << " (none)\n";
        return;
    }
    for (const std::string& id : ids) {
        output << ' ' << id;
    }
    output << '\n';
}

int discover_functions_file(const std::string_view rom_path, std::ostream& output,
                            std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    output << "ROM function discovery\n"
           << "  File: " << image.path().string() << '\n'
           << "  Seeds: reset entry $0100 and five interrupt vectors\n"
           << "  Mapper state: not modeled; switchable-window banks use a physical-bank assumption\n";
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }

    const analysis::FunctionDiscoveryResult result = analysis::discover_functions(image);
    for (const analysis::FunctionInfo& function : result.functions) {
        output << function.id << ' ' << function.name << " B" << std::uppercase << std::hex
               << std::setfill('0') << std::setw(4) << function.bank << ":$"
               << std::setw(4) << function.cpu_address << std::dec << std::setfill(' ')
               << ' ' << static_cast<unsigned>(function.confidence_percent) << "% ["
               << analysis::function_start_evidence_name(function.start_evidence)
               << "]; instructions=" << function.reachable_instruction_count << '\n';
        print_function_ids(output, "callers", function.callers);
        print_function_ids(output, "callees", function.callees);
    }
    output << "Functions discovered: " << result.functions.size()
           << "; function-scoped instructions analyzed: " << result.analyzed_instructions << '\n';
    return image.is_valid() && !result.cancelled ? kSuccess : kAnalysisFailed;
}

int build_cfg_file(const std::string_view rom_path, std::ostream& output,
                   std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }
    const analysis::FunctionDiscoveryResult functions = analysis::discover_functions(image);
    const analysis::ControlFlowGraphResult graphs =
        analysis::build_control_flow_graphs(image, functions.functions);
    output << analysis::format_control_flow_graphs_as_dot(graphs);
    return image.is_valid() && !functions.cancelled && !graphs.cancelled
        ? kSuccess : kAnalysisFailed;
}

int build_xrefs_file(const std::string_view rom_path, std::ostream& output,
                     std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    output << "ROM cross references\n"
           << "  Identity: physical bank + CPU address\n"
           << "  Mapper state: not modeled; switch-window references use a default-bank assumption\n"
           << "  Data pointers are conservative candidates, not confirmed pointers\n";
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }

    const analysis::CrossReferenceResult result = analysis::build_cross_references(image);
    for (const analysis::CrossReference& reference : result.references) {
        output << analysis::format_cross_reference(reference) << '\n';
    }
    output << "Cross references: " << result.references.size()
           << "; functions: " << result.functions_analyzed
           << "; instructions: " << result.instructions_analyzed << '\n';
    if (result.cancelled) {
        output << "Cross-reference analysis cancelled.\n";
    }
    return image.is_valid() && !result.cancelled ? kSuccess : kAnalysisFailed;
}

int analyze_memory_file(const std::string_view rom_path, std::ostream& output,
                        std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    memory::MemoryMapContext context;
    context.hardware_mode = memory::hardware_mode_from_cgb_flag(image.header().cgb_flag);
    context.switchable_rom_bank = image.actual_bank_count() > 1U
        ? std::optional<std::uint16_t>(std::uint16_t{1U}) : std::nullopt;
    output << "Game Boy memory map and data analysis\n"
           << "  Hardware mode: " << memory::hardware_mode_name(context.hardware_mode) << '\n'
           << "  ROM banks: " << image.actual_bank_count()
           << "; mapper-selected bank state is not known statically\n";
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }

    output << "Address map\n";
    for (const memory::MemoryRegionDescriptor& region : memory::memory_region_table()) {
        const memory::MemoryMapping mapping = memory::map_memory_address(region.start, context);
        output << "  $" << std::uppercase << std::hex << std::setfill('0') << std::setw(4)
               << region.start << "-$" << std::setw(4) << region.end << std::dec
               << "  " << region.name << "  " << region.description;
        if (mapping.bank.has_value()) {
            output << " (bank " << *mapping.bank;
            output << (mapping.bank_selection_known ? ")" : ", assumption)");
        }
        if (mapping.canonical_address != mapping.address) {
            output << " -> $" << std::uppercase << std::hex << std::setw(4)
                   << mapping.canonical_address << std::dec;
        }
        output << '\n';
    }

    output << "Hardware registers\n";
    for (const memory::HardwareRegisterInfo& reg : memory::hardware_register_table()) {
        output << "  $" << std::uppercase << std::hex << std::setfill('0') << std::setw(4)
               << reg.address << std::dec << " " << reg.name << " ["
               << (reg.readable ? 'R' : '-') << (reg.writable ? 'W' : '-') << "] "
               << reg.description << '\n';
    }

    output << "Data candidates\n"
           << "  Text and pointer tables remain candidates; automatic graphics/compression decoding is deferred.\n";
    const analysis::MemoryDataResult result = analysis::analyze_memory_and_data(image);
    for (const analysis::DataCandidate& candidate : result.candidates) {
        output << analysis::format_data_candidate(candidate) << '\n';
    }
    output << "Candidates: " << result.candidates.size()
           << "; referenced ROM locations: " << result.direct_rom_references
           << "; pointer tables: " << result.pointer_tables
           << "; text strings: " << result.text_strings << '\n';
    if (result.cancelled) {
        output << "Memory/data analysis cancelled.\n";
    }
    return image.is_valid() && !result.cancelled ? kSuccess : kAnalysisFailed;
}

int build_ir_file(const std::string_view rom_path, std::ostream& output,
                  std::ostream& errors) {
    rom::RomLoadError load_error;
    auto loaded_rom = rom::Rom::load_file(std::filesystem::path(std::string(rom_path)), load_error);
    if (!loaded_rom.has_value()) {
        errors << "error: " << load_error.message << '\n';
        return kAnalysisFailed;
    }

    const rom::Rom& image = *loaded_rom;
    for (const rom::RomIssue& issue : image.issues()) {
        errors << (issue.severity == rom::RomIssueSeverity::Error ? "error: " : "warning: ")
               << issue.message << '\n';
    }
    const ir::IRModule module = ir::build_ir(image);
    output << ir::format_ir_module(module);
    return image.is_valid() && !module.cancelled ? kSuccess : kAnalysisFailed;
}

}  // namespace

int run_cli(const int argc, const char* const argv[], std::ostream& output,
            std::ostream& errors, core::Logger& logger) {
    if (argc <= 1 || argv == nullptr) {
        print_usage(output);
        return kSuccess;
    }

    const std::string_view first_argument{argv[1]};
    if (first_argument == "--help" || first_argument == "-h" || first_argument == "help") {
        print_usage(output);
        return kSuccess;
    }
    if (first_argument == "--version" || first_argument == "-V") {
        output << "tool " << TOOL_VERSION_STRING << '\n';
        return kSuccess;
    }

    std::string_view command = first_argument;
    int argument_count = argc - 2;
    const char* const* command_arguments = argv + 2;

    if (has_rom_extension(first_argument)) {
        command = "analyze";
        argument_count = argc - 1;
        command_arguments = argv + 1;
    }

    if (command == "analyze" || command == "disassemble" || command == "classify" ||
        command == "functions" || command == "cfg" || command == "xrefs" ||
        command == "memory" || command == "ir") {
        if (argument_count != 1 || command_arguments[0] == nullptr || command_arguments[0][0] == '\0') {
            errors << "error: '" << command << "' expects exactly one ROM path\n";
            return kInvalidArguments;
        }
        if (command == "analyze") {
            return analyze_rom(command_arguments[0], output, errors);
        }
        if (command == "disassemble") {
            return disassemble_rom_file(command_arguments[0], output, errors);
        }
        if (command == "classify") {
            return classify_rom_file(command_arguments[0], output, errors);
        }
        if (command == "functions") {
            return discover_functions_file(command_arguments[0], output, errors);
        }
        if (command == "xrefs") {
            return build_xrefs_file(command_arguments[0], output, errors);
        }
        if (command == "memory") {
            return analyze_memory_file(command_arguments[0], output, errors);
        }
        if (command == "ir") {
            return build_ir_file(command_arguments[0], output, errors);
        }
        return build_cfg_file(command_arguments[0], output, errors);
    }

    if (command == "decompile") {
        if (argument_count != 3 || command_arguments[0] == nullptr || command_arguments[1] == nullptr ||
            command_arguments[2] == nullptr || std::string_view{command_arguments[1]} != "--output" ||
            command_arguments[0][0] == '\0' || command_arguments[2][0] == '\0') {
            errors << "error: 'decompile' expects <rom.gb> --output <directory>\n";
            return kInvalidArguments;
        }
        return report_unavailable(command, logger);
    }

    errors << "error: unknown command or option '" << first_argument << "'\n"
           << "Run 'tool --help' for usage.\n";
    return kInvalidArguments;
}

}  // namespace tool::cli
