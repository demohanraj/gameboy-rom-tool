#include "tool/analysis/CodeDataAnalyzer.h"
#include "tool/analysis/ControlFlowGraph.h"
#include "tool/analysis/CrossReferences.h"
#include "tool/analysis/FunctionDiscovery.h"
#include "tool/analysis/MemoryDataAnalyzer.h"
#include "tool/disasm/Disassembler.h"
#include "tool/memory/MemoryMap.h"
#include "tool/ir/IR.h"
#include "tool/rom/Rom.h"

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kWindowClassName[] = L"ToolRomAnalysisWindow";
constexpr wchar_t kWindowTitle[] = L"TOOL - Game Boy ROM Analysis Demo";
constexpr UINT kUiMessage = WM_APP + 1U;
constexpr int kOpenButton = 1001;
constexpr int kAnalyzeButton = 1002;
constexpr int kDisassembleButton = 1003;
constexpr int kClassifyButton = 1004;
constexpr int kCancelButton = 1005;
constexpr int kPathLabel = 1006;
constexpr int kOutputEdit = 1007;
constexpr int kStatusLabel = 1008;
constexpr int kProgressBar = 1009;
constexpr int kFunctionsButton = 1010;
constexpr int kCfgButton = 1011;
constexpr int kXrefsButton = 1012;
constexpr int kMemoryButton = 1013;
constexpr int kIRButton = 1014;
constexpr std::size_t kPreviewLineLimit = 10000U;
constexpr std::size_t kOutputBatchCharacters = 48U * 1024U;

enum class Operation {
    Metadata,
    Disassembly,
    Classification,
    Functions,
    ControlFlowGraph,
    CrossReferences,
    MemoryData,
    IntermediateRepresentation,
};

enum class UiMessageKind {
    AppendText,
    Progress,
    Finished,
};

struct UiMessage {
    UiMessageKind kind{UiMessageKind::AppendText};
    std::wstring text;
    int percent{};
};

struct AppState {
    HWND window{};
    HWND open_button{};
    HWND analyze_button{};
    HWND disassemble_button{};
    HWND classify_button{};
    HWND functions_button{};
    HWND cfg_button{};
    HWND xrefs_button{};
    HWND memory_button{};
    HWND ir_button{};
    HWND cancel_button{};
    HWND path_label{};
    HWND output_edit{};
    HWND status_label{};
    HWND progress_bar{};
    HFONT font{};
    std::filesystem::path rom_path;
    std::jthread worker;
    bool closing{};
};

std::wstring utf8_to_wide(const std::string_view value) {
    if (value.empty()) {
        return {};
    }
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return L"[text too long]";
    }
    const int input_size = static_cast<int>(value.size());
    int required = MultiByteToWideChar(CP_UTF8, 0, value.data(), input_size, nullptr, 0);
    UINT code_page = CP_UTF8;
    if (required <= 0) {
        code_page = CP_ACP;
        required = MultiByteToWideChar(code_page, 0, value.data(), input_size, nullptr, 0);
    }
    if (required <= 0) {
        return L"[text conversion failed]";
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    const int converted = MultiByteToWideChar(code_page, 0, value.data(), input_size,
                                              result.data(), required);
    if (converted <= 0) {
        return L"[text conversion failed]";
    }
    result.resize(static_cast<std::size_t>(converted));
    return result;
}

bool post_ui_message(const HWND window, UiMessage message) {
    auto payload = std::make_unique<UiMessage>(std::move(message));
    if (PostMessageW(window, kUiMessage, 0,
                     reinterpret_cast<LPARAM>(payload.get())) == FALSE) {
        return false;
    }
    static_cast<void>(payload.release());
    return true;
}

void post_progress(const HWND window, const std::wstring_view stage,
                   const int percent, const std::uint16_t bank) {
    std::wostringstream text;
    text << stage;
    if (percent >= 0) {
        text << L"  " << percent << L"%";
    }
    text << L"    Bank " << std::uppercase << std::hex << std::setfill(L'0')
         << std::setw(4) << bank;
    post_ui_message(window, {UiMessageKind::Progress, text.str(), percent});
}

class OutputBatcher {
public:
    explicit OutputBatcher(const HWND window) : window_(window) {}

    void line(const std::string_view value) {
        if (emitted_lines_ >= kPreviewLineLimit) {
            ++suppressed_lines_;
            return;
        }
        buffer_ += utf8_to_wide(value);
        buffer_ += L"\r\n";
        ++emitted_lines_;
        if (buffer_.size() >= kOutputBatchCharacters) {
            flush();
        }
    }

    void line(const std::wstring_view value) {
        if (emitted_lines_ >= kPreviewLineLimit) {
            ++suppressed_lines_;
            return;
        }
        buffer_.append(value);
        buffer_ += L"\r\n";
        ++emitted_lines_;
        if (buffer_.size() >= kOutputBatchCharacters) {
            flush();
        }
    }

    [[nodiscard]] bool preview_full() const noexcept {
        return emitted_lines_ >= kPreviewLineLimit;
    }

    void add_limit_note() {
        if (suppressed_lines_ != 0U) {
            buffer_ += L"Display preview reached its 10,000-line limit; analysis continued. "
                       L"Use the CLI for a complete text listing.\r\n";
        }
    }

    void flush() {
        if (buffer_.empty()) {
            return;
        }
        post_ui_message(window_, {UiMessageKind::AppendText, std::move(buffer_), 0});
        buffer_.clear();
    }

private:
    HWND window_{};
    std::wstring buffer_;
    std::size_t emitted_lines_{};
    std::size_t suppressed_lines_{};
};

std::wstring format_classification_record(
    const tool::analysis::ClassificationRecord& record) {
    std::wostringstream text;
    text << utf8_to_wide(tool::analysis::classification_name(record.classification)) << L' ';
    if (record.confidence_percent == 0U) {
        text << L"--% ";
    } else {
        text << static_cast<unsigned>(record.confidence_percent) << L"% ";
    }
    if (record.instruction.has_value() || record.raw_byte.has_value()) {
        tool::disasm::DisassemblyEntry entry;
        entry.bank = record.bank;
        entry.cpu_address = record.cpu_address;
        entry.rom_offset = record.rom_offset;
        entry.instruction = record.instruction;
        if (record.raw_byte.has_value()) {
            entry.raw_byte = *record.raw_byte;
        }
        text << utf8_to_wide(tool::disasm::format_disassembly_entry(entry));
    } else {
        text << L'B' << std::uppercase << std::hex << std::setfill(L'0')
             << std::setw(4) << record.bank << L":$" << std::setw(4)
             << record.cpu_address << L" [ROM $" << std::setw(6)
             << record.rom_offset << L"] length=0x" << record.length;
    }
    text << L" ; evidence: " << utf8_to_wide(tool::analysis::evidence_name(record.evidence));
    return text.str();
}

int progress_percent(const std::size_t offset, const std::size_t total) noexcept {
    if (total == 0U) {
        return 100;
    }
    const std::uint64_t numerator = static_cast<std::uint64_t>(offset) * 100U;
    const std::uint64_t bounded = std::min(numerator / total, std::uint64_t{100U});
    return static_cast<int>(bounded);
}

void print_rom_issues(const tool::rom::Rom& image, OutputBatcher& output) {
    for (const tool::rom::RomIssue& issue : image.issues()) {
        const std::string prefix = issue.severity == tool::rom::RomIssueSeverity::Error
            ? "ERROR: " : "Warning: ";
        output.line(prefix + issue.message);
    }
}

void print_metadata(const tool::rom::Rom& image, OutputBatcher& output) {
    const tool::rom::RomHeader& header = image.header();
    std::ostringstream text;
    text << "Title: " << (header.title.empty() ? "(untitled)" : header.title)
         << "\nCartridge: " << header.cartridge.type_name
         << "\nMapper: " << tool::rom::mapper_name(header.cartridge.mapper)
         << "\nROM: " << image.actual_size_bytes() / 1024U << " KiB in "
         << image.actual_bank_count() << " physical banks"
         << "\nDeclared ROM banks: " << header.declared_rom_bank_count
         << "\nNintendo logo: " << (header.nintendo_logo_valid ? "valid" : "invalid")
         << "\nHeader checksum: " << (header.header_checksum_valid ? "valid" : "invalid")
         << "\nGlobal checksum: " << (header.global_checksum_valid ? "valid" : "invalid")
         << "\nROM status: " << (image.is_valid() ? "valid" : "invalid");
    output.line(text.str());
    print_rom_issues(image, output);
}

void run_worker(const HWND window, const std::filesystem::path rom_path,
                const Operation operation, const std::stop_token stop_token) {
    OutputBatcher output(window);
    post_progress(window, L"Loading ROM", 0, 0U);
    output.line(std::string("File: ") + rom_path.string());

    try {
        tool::rom::RomLoadError load_error;
        const auto loaded = tool::rom::Rom::load_file(rom_path, load_error);
        if (!loaded.has_value()) {
            output.line(std::string("ERROR: ") + load_error.message);
        } else {
            const tool::rom::Rom& image = *loaded;
            if (operation == Operation::Metadata) {
                post_progress(window, L"Reading cartridge metadata", 100, 0U);
                print_metadata(image, output);
            } else if (operation == Operation::Disassembly) {
                output.line("Physical-bank linear disassembly (not code/data classified)");
                print_rom_issues(image, output);
                std::size_t visited = 0U;
                std::uint16_t previous_bank = std::numeric_limits<std::uint16_t>::max();
                const tool::disasm::DisassemblyStats stats = tool::disasm::disassemble_rom(
                    image,
                    [&](const tool::disasm::DisassemblyEntry& entry) {
                        if (!output.preview_full()) {
                            output.line(tool::disasm::format_disassembly_entry(entry));
                        }
                        ++visited;
                        if (visited % 256U == 0U || entry.bank != previous_bank) {
                            post_progress(window, L"Disassembling",
                                progress_percent(entry.rom_offset, image.actual_size_bytes()),
                                entry.bank);
                            previous_bank = entry.bank;
                        }
                        return !stop_token.stop_requested();
                    }, stop_token);
                std::ostringstream summary;
                summary << "Disassembly entries: " << stats.entries << " (decoded: "
                        << stats.decoded_instructions << ", undocumented: "
                        << stats.illegal_opcodes << ", incomplete bytes: "
                        << stats.undecoded_bytes << ')';
                output.line(summary.str());
                if (stats.cancelled) {
                    output.line("Analysis cancelled.");
                }
            } else if (operation == Operation::Classification) {
                output.line("Static reachable-code analysis; confidence is evidence strength, not probability.");
                output.line("Seeds: cartridge entry $0100 and fixed interrupt vectors.");
                output.line("MBC register state is not modeled; switch-window bank choices are assumptions.");
                print_rom_issues(image, output);
                post_progress(window, L"Tracing reachable control flow", -1, 0U);
                std::size_t visited = 0U;
                const tool::analysis::ReachabilityStats stats =
                    tool::analysis::analyze_reachable_code(
                        image,
                        [&](const tool::analysis::ClassificationRecord& record) {
                            if (!output.preview_full()) {
                                output.line(format_classification_record(record));
                            }
                            ++visited;
                            if (visited % 128U == 0U) {
                                post_progress(window, L"Classifying regions",
                                    progress_percent(record.rom_offset, image.actual_size_bytes()),
                                    record.bank);
                            }
                            return !stop_token.stop_requested();
                        }, stop_token);
                std::ostringstream summary;
                summary << "Reachability: " << stats.reachable_instructions
                        << " instructions (" << stats.code_instructions << " CODE, "
                        << stats.possible_code_instructions << " POSSIBLE_CODE); regions: "
                        << stats.data_regions << " DATA, " << stats.possible_data_regions
                        << " POSSIBLE_DATA, " << stats.unknown_regions << " UNKNOWN.";
                output.line(summary.str());
                if (stats.cancelled) {
                    output.line("Analysis cancelled.");
                }
            } else if (operation == Operation::Functions) {
                output.line("Function discovery; reset entry, interrupt vectors, and direct CALL/RST targets.");
                output.line("Mapper state is not modeled; switchable-window banks use physical-bank assumptions.");
                post_progress(window, L"Discovering functions", -1, 0U);
                const tool::analysis::FunctionDiscoveryResult result =
                    tool::analysis::discover_functions(image, stop_token);
                for (const tool::analysis::FunctionInfo& function : result.functions) {
                    std::ostringstream line;
                    line << function.id << ' ' << function.name << " B" << std::uppercase
                         << std::hex << std::setfill('0') << std::setw(4) << function.bank
                         << ":$" << std::setw(4) << function.cpu_address << std::dec
                         << ' ' << static_cast<unsigned>(function.confidence_percent) << "% ["
                         << tool::analysis::function_start_evidence_name(function.start_evidence)
                         << "]; instructions=" << function.reachable_instruction_count;
                    output.line(line.str());
                    const auto append_ids = [&output](const char* label,
                        const std::vector<std::string>& ids) {
                        std::ostringstream references;
                        references << "  " << label << ':';
                        if (ids.empty()) {
                            references << " (none)";
                        } else {
                            for (const std::string& id : ids) {
                                references << ' ' << id;
                            }
                        }
                        output.line(references.str());
                    };
                    append_ids("callers", function.callers);
                    append_ids("callees", function.callees);
                }
                std::ostringstream summary;
                summary << "Functions discovered: " << result.functions.size()
                        << "; function-scoped instructions analyzed: "
                        << result.analyzed_instructions;
                output.line(summary.str());
                if (result.cancelled) {
                    output.line("Function discovery cancelled.");
                }
            } else if (operation == Operation::MemoryData) {
                tool::memory::MemoryMapContext context;
                context.hardware_mode = tool::memory::hardware_mode_from_cgb_flag(
                    image.header().cgb_flag);
                context.switchable_rom_bank = image.actual_bank_count() > 1U
                    ? std::optional<std::uint16_t>(std::uint16_t{1U}) : std::nullopt;
                output.line("Game Boy memory map; selected mapper banks are assumptions.");
                output.line("Hardware mode: " + std::string(
                    tool::memory::hardware_mode_name(context.hardware_mode)));
                for (const tool::memory::MemoryRegionDescriptor& region :
                     tool::memory::memory_region_table()) {
                    const tool::memory::MemoryMapping mapping =
                        tool::memory::map_memory_address(region.start, context);
                    std::ostringstream line;
                    line << '$' << std::uppercase << std::hex << std::setfill('0')
                         << std::setw(4) << region.start << "-$" << std::setw(4)
                         << region.end << "  " << region.name << "  " << region.description;
                    if (mapping.bank.has_value()) {
                        line << " (bank " << std::dec << *mapping.bank
                             << (mapping.bank_selection_known ? ")" : ", assumption)");
                    }
                    if (mapping.canonical_address != mapping.address) {
                        line << " -> $" << std::uppercase << std::hex << std::setw(4)
                             << mapping.canonical_address;
                    }
                    output.line(line.str());
                }
                output.line("Hardware registers (R=readable, W=writable):");
                for (const tool::memory::HardwareRegisterInfo& reg :
                     tool::memory::hardware_register_table()) {
                    std::ostringstream line;
                    line << '$' << std::uppercase << std::hex << std::setfill('0')
                         << std::setw(4) << reg.address << std::dec << ' ' << reg.name
                         << " [" << (reg.readable ? 'R' : '-') << (reg.writable ? 'W' : '-')
                         << "] " << reg.description;
                    output.line(line.str());
                }
                output.line("Data candidates (tentative):");
                post_progress(window, L"Scanning referenced data, pointers, and text", -1, 0U);
                const tool::analysis::MemoryDataResult result =
                    tool::analysis::analyze_memory_and_data(image, stop_token);
                for (const tool::analysis::DataCandidate& candidate : result.candidates) {
                    if (!output.preview_full()) {
                        output.line(tool::analysis::format_data_candidate(candidate));
                    }
                }
                std::ostringstream summary;
                summary << "Candidates: " << result.candidates.size()
                        << "; referenced ROM locations: " << result.direct_rom_references
                        << "; pointer tables: " << result.pointer_tables
                        << "; text strings: " << result.text_strings;
                output.line(summary.str());
                if (result.cancelled) {
                    output.line("Memory/data analysis cancelled.");
                }
            } else if (operation == Operation::IntermediateRepresentation) {
                output.line("Structured opcode-level IR; CPU semantic lifting is Phase 10.");
                print_rom_issues(image, output);
                post_progress(window, L"Building opcode-level IR", -1, 0U);
                const tool::ir::IRModule module = tool::ir::build_ir(image, stop_token);
                std::istringstream report(tool::ir::format_ir_module(module));
                std::string line;
                while (std::getline(report, line)) {
                    output.line(line);
                }
            } else if (operation == Operation::CrossReferences) {
                output.line("Cross references use physical bank + CPU address identity.");
                output.line("Mapper state is not modeled; data-pointer matches are conservative candidates.");
                print_rom_issues(image, output);
                post_progress(window, L"Building cross-reference index", -1, 0U);
                const tool::analysis::CrossReferenceResult result =
                    tool::analysis::build_cross_references(image, stop_token);
                for (const tool::analysis::CrossReference& reference : result.references) {
                    if (!output.preview_full()) {
                        output.line(tool::analysis::format_cross_reference(reference));
                    }
                }
                std::ostringstream summary;
                summary << "Cross references: " << result.references.size()
                        << "; functions: " << result.functions_analyzed
                        << "; instructions: " << result.instructions_analyzed;
                output.line(summary.str());
                if (result.cancelled) {
                    output.line("Cross-reference analysis cancelled.");
                }
            } else {
                output.line("Control-flow graphs; edge labels preserve branch, call, return, and indirect flow.");
                post_progress(window, L"Building control-flow graphs", -1, 0U);
                const tool::analysis::FunctionDiscoveryResult functions =
                    tool::analysis::discover_functions(image, stop_token);
                if (functions.cancelled) {
                    output.line("Function discovery cancelled before CFG construction.");
                } else {
                    const tool::analysis::ControlFlowGraphResult graphs =
                        tool::analysis::build_control_flow_graphs(image, functions.functions,
                                                                  stop_token);
                    for (const tool::analysis::ControlFlowGraph& graph : graphs.graphs) {
                        output.line(graph.function_name + " (" + graph.function_id + ")");
                        for (const tool::analysis::BasicBlock& block : graph.blocks) {
                            std::ostringstream block_line;
                            block_line << block.id << " B" << std::uppercase << std::hex
                                       << std::setfill('0') << std::setw(4) << block.bank
                                       << ":$" << std::setw(4) << block.start_address
                                       << " instructions=" << std::dec << block.instructions.size();
                            output.line(block_line.str());
                            for (const tool::cpu::Instruction& instruction : block.instructions) {
                                output.line("  " + tool::cpu::format_instruction(instruction));
                            }
                            if (block.decode_error.has_value()) {
                                output.line("  <decode error>");
                            }
                        }
                        for (const tool::analysis::CFGEdge& edge : graph.edges) {
                            std::ostringstream edge_line;
                            edge_line << edge.source_block_id << " --"
                                      << tool::analysis::cfg_edge_kind_name(edge.kind);
                            if (edge.condition_outcome.has_value()) {
                                edge_line << " ("
                                          << tool::analysis::condition_outcome_name(
                                                 *edge.condition_outcome)
                                          << ')';
                            }
                            edge_line << "--> ";
                            if (edge.target_block_id.has_value()) {
                                edge_line << *edge.target_block_id;
                            } else if (edge.target_function_id.has_value()) {
                                edge_line << *edge.target_function_id;
                            } else if (edge.target_bank.has_value() && edge.target_address.has_value()) {
                                edge_line << 'B' << std::uppercase << std::hex << std::setfill('0')
                                          << std::setw(4) << *edge.target_bank << ":$"
                                          << std::setw(4) << *edge.target_address;
                            } else {
                                edge_line << "<external/unknown>";
                            }
                            output.line(edge_line.str());
                        }
                    }
                    std::ostringstream summary;
                    summary << "CFGs: " << graphs.graphs.size()
                            << "; instructions decoded: " << graphs.instructions_analyzed;
                    output.line(summary.str());
                    if (graphs.cancelled) {
                        output.line("CFG construction cancelled.");
                    }
                }
            }
            output.add_limit_note();
        }
    } catch (const std::exception& error) {
        output.line(std::string("ERROR: ") + error.what());
    }

    output.flush();
    const bool cancelled = stop_token.stop_requested();
    post_ui_message(window, {UiMessageKind::Finished,
                            cancelled ? L"Cancelled" : L"Ready", 100});
}

AppState* app_state(const HWND window) noexcept {
    return reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
}

void set_control_font(const HWND control, const HFONT font) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

HWND create_control(const HWND parent, const wchar_t* class_name,
                    const wchar_t* text, const DWORD style, const int id,
                    const HFONT font) {
    HWND control = CreateWindowExW(0, class_name, text, style,
        0, 0, 100, 28, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr), nullptr);
    if (control != nullptr) {
        set_control_font(control, font);
    }
    return control;
}

void enable_controls(AppState& state, const bool busy) {
    EnableWindow(state.open_button, busy ? FALSE : TRUE);
    EnableWindow(state.analyze_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.disassemble_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.classify_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.functions_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.cfg_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.xrefs_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.memory_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.ir_button, !busy && !state.rom_path.empty() ? TRUE : FALSE);
    EnableWindow(state.cancel_button, busy ? TRUE : FALSE);
}

void layout_controls(AppState& state, const int width, const int height) {
    constexpr int margin = 12;
    constexpr int button_height = 30;
    constexpr int gap = 8;
    int x = margin;
    const auto place_button = [&](const HWND control, const int button_width) {
        MoveWindow(control, x, margin, button_width, button_height, TRUE);
        x += button_width + gap;
    };
    place_button(state.open_button, 104);
    place_button(state.analyze_button, 126);
    place_button(state.disassemble_button, 126);
    place_button(state.classify_button, 126);
    place_button(state.functions_button, 126);
    place_button(state.cfg_button, 76);
    place_button(state.xrefs_button, 82);
    place_button(state.memory_button, 90);
    place_button(state.ir_button, 54);
    place_button(state.cancel_button, 88);
    MoveWindow(state.path_label, margin, 50, std::max(100, width - margin * 2), 24, TRUE);
    const int footer_y = std::max(120, height - 42);
    MoveWindow(state.status_label, margin, footer_y - 26,
               std::max(100, width - margin * 2), 22, TRUE);
    MoveWindow(state.progress_bar, margin, footer_y,
               std::max(100, width - margin * 2), 16, TRUE);
    MoveWindow(state.output_edit, margin, 82,
               std::max(100, width - margin * 2), std::max(50, footer_y - 94), TRUE);
}

void open_rom_dialog(AppState& state) {
    std::array<wchar_t, 32768> file_name{};
    if (!state.rom_path.empty()) {
        const std::wstring initial = state.rom_path.wstring();
        const std::size_t copy_size = std::min(initial.size(), file_name.size() - 1U);
        std::copy_n(initial.data(), copy_size, file_name.data());
    }
    constexpr wchar_t kFilter[] =
        L"Game Boy ROMs (*.gb;*.gbc)\0*.gb;*.gbc\0All files (*.*)\0*.*\0\0";
    OPENFILENAMEW dialog{};
    dialog.lStructSize = static_cast<DWORD>(sizeof(dialog));
    dialog.hwndOwner = state.window;
    dialog.lpstrFilter = kFilter;
    dialog.lpstrFile = file_name.data();
    dialog.nMaxFile = static_cast<DWORD>(file_name.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    dialog.lpstrTitle = L"Open a Game Boy ROM";
    if (GetOpenFileNameW(&dialog) != FALSE) {
        state.rom_path = std::filesystem::path(file_name.data());
        SetWindowTextW(state.path_label, state.rom_path.c_str());
        SetWindowTextW(state.output_edit,
            L"ROM selected. Choose Analyze, Disassemble, Classify, Functions, CFG, Xrefs, Memory, or IR.\r\n"
            L"The GUI shows a bounded preview; the core analysis runs off the UI thread.");
        enable_controls(state, false);
    }
}

void start_operation(AppState& state, const Operation operation) {
    if (state.rom_path.empty() || state.worker.joinable()) {
        return;
    }
    SetWindowTextW(state.output_edit, L"");
    SetWindowTextW(state.status_label, L"Starting analysis...");
    SendMessageW(state.progress_bar, PBM_SETPOS, 0, 0);
    enable_controls(state, true);
    try {
        const HWND window = state.window;
        const std::filesystem::path path = state.rom_path;
        state.worker = std::jthread([window, path, operation](const std::stop_token stop_token) {
            run_worker(window, path, operation, stop_token);
        });
    } catch (const std::exception& error) {
        enable_controls(state, false);
        SetWindowTextW(state.status_label, L"Could not start analysis worker");
        MessageBoxW(state.window, utf8_to_wide(error.what()).c_str(),
                    kWindowTitle, MB_OK | MB_ICONERROR);
    }
}

LRESULT CALLBACK window_proc(const HWND window, const UINT message,
                             const WPARAM w_param, const LPARAM l_param) {
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(l_param);
        auto* state = static_cast<AppState*>(create->lpCreateParams);
        state->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
    }
    AppState* state = app_state(window);
    switch (message) {
        case WM_CREATE: {
            if (state == nullptr) {
                return -1;
            }
            state->font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            state->open_button = create_control(window, L"BUTTON", L"Open ROM...",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kOpenButton, state->font);
            state->analyze_button = create_control(window, L"BUTTON", L"Analyze",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kAnalyzeButton, state->font);
            state->disassemble_button = create_control(window, L"BUTTON", L"Disassemble",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kDisassembleButton, state->font);
            state->classify_button = create_control(window, L"BUTTON", L"Classify",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kClassifyButton, state->font);
            state->functions_button = create_control(window, L"BUTTON", L"Functions",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kFunctionsButton, state->font);
            state->cfg_button = create_control(window, L"BUTTON", L"CFG",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kCfgButton, state->font);
            state->xrefs_button = create_control(window, L"BUTTON", L"Xrefs",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kXrefsButton, state->font);
            state->memory_button = create_control(window, L"BUTTON", L"Memory",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kMemoryButton, state->font);
            state->ir_button = create_control(window, L"BUTTON", L"IR",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kIRButton, state->font);
            state->cancel_button = create_control(window, L"BUTTON", L"Cancel",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, kCancelButton, state->font);
            state->path_label = create_control(window, L"STATIC", L"No ROM selected",
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_PATHELLIPSIS, kPathLabel, state->font);
            state->output_edit = create_control(window, L"EDIT", L"Select a .gb or .gbc ROM to begin.\r\n"
                L"Analyze shows cartridge metadata. Disassemble lists a linear candidate stream.\r\n"
                L"Classify reports code/data confidence. Functions lists discovered entries and call links.\r\n"
                L"CFG shows control flow. Xrefs lists bank-aware references. Memory reports address regions and data candidates. IR shows structured opcode records.",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_LEFT | ES_MULTILINE |
                ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
                kOutputEdit, state->font);
            state->status_label = create_control(window, L"STATIC", L"Ready",
                WS_CHILD | WS_VISIBLE | SS_LEFT, kStatusLabel, state->font);
            state->progress_bar = create_control(window, PROGRESS_CLASSW, L"",
                WS_CHILD | WS_VISIBLE | PBS_SMOOTH, kProgressBar, state->font);
            if (state->output_edit != nullptr) {
                SendMessageW(state->output_edit, EM_SETLIMITTEXT, 2000000, 0);
            }
            INITCOMMONCONTROLSEX common_controls{
                static_cast<DWORD>(sizeof(common_controls)), ICC_PROGRESS_CLASS};
            InitCommonControlsEx(&common_controls);
            enable_controls(*state, false);
            RECT client{};
            GetClientRect(window, &client);
            layout_controls(*state, client.right - client.left, client.bottom - client.top);
            return 0;
        }
        case WM_SIZE:
            if (state != nullptr) {
                layout_controls(*state, LOWORD(l_param), HIWORD(l_param));
            }
            return 0;
        case WM_COMMAND:
            if (state == nullptr) {
                return 0;
            }
            switch (LOWORD(w_param)) {
                case kOpenButton:
                    open_rom_dialog(*state);
                    return 0;
                case kAnalyzeButton:
                    start_operation(*state, Operation::Metadata);
                    return 0;
                case kDisassembleButton:
                    start_operation(*state, Operation::Disassembly);
                    return 0;
                case kClassifyButton:
                    start_operation(*state, Operation::Classification);
                    return 0;
                case kFunctionsButton:
                    start_operation(*state, Operation::Functions);
                    return 0;
                case kCfgButton:
                    start_operation(*state, Operation::ControlFlowGraph);
                    return 0;
                case kXrefsButton:
                    start_operation(*state, Operation::CrossReferences);
                    return 0;
                case kMemoryButton:
                    start_operation(*state, Operation::MemoryData);
                    return 0;
                case kIRButton:
                    start_operation(*state, Operation::IntermediateRepresentation);
                    return 0;
                case kCancelButton:
                    if (state->worker.joinable()) {
                        state->worker.request_stop();
                        SetWindowTextW(state->status_label, L"Cancellation requested...");
                    }
                    return 0;
                default:
                    break;
            }
            break;
        case kUiMessage: {
            std::unique_ptr<UiMessage> payload(reinterpret_cast<UiMessage*>(l_param));
            if (!payload || state == nullptr) {
                return 0;
            }
            if (payload->kind == UiMessageKind::AppendText) {
                const LRESULT length = SendMessageW(state->output_edit, WM_GETTEXTLENGTH, 0, 0);
                SendMessageW(state->output_edit, EM_SETSEL,
                    static_cast<WPARAM>(length), static_cast<LPARAM>(length));
                SendMessageW(state->output_edit, EM_REPLACESEL, FALSE,
                    reinterpret_cast<LPARAM>(payload->text.c_str()));
            } else if (payload->kind == UiMessageKind::Progress) {
                SetWindowTextW(state->status_label, payload->text.c_str());
                if (payload->percent >= 0) {
                    SendMessageW(state->progress_bar, PBM_SETMARQUEE, FALSE, 0);
                    SendMessageW(state->progress_bar, PBM_SETPOS,
                        static_cast<WPARAM>(payload->percent), 0);
                } else {
                    SendMessageW(state->progress_bar, PBM_SETMARQUEE, TRUE, 40);
                }
            } else {
                if (state->worker.joinable()) {
                    state->worker.join();
                }
                SendMessageW(state->progress_bar, PBM_SETMARQUEE, FALSE, 0);
                SendMessageW(state->progress_bar, PBM_SETPOS, 100, 0);
                SetWindowTextW(state->status_label, payload->text.c_str());
                enable_controls(*state, false);
                if (state->closing) {
                    DestroyWindow(window);
                }
            }
            return 0;
        }
        case WM_CLOSE:
            if (state != nullptr && state->worker.joinable()) {
                state->closing = true;
                state->worker.request_stop();
                SetWindowTextW(state->status_label, L"Cancelling before closing...");
                EnableWindow(state->cancel_button, FALSE);
                return 0;
            }
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            if (state != nullptr && state->font != nullptr) {
                DeleteObject(state->font);
                state->font = nullptr;
            }
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

}  // namespace

int WINAPI wWinMain(const HINSTANCE instance, const HINSTANCE, const PWSTR,
                    const int show_command) {
    INITCOMMONCONTROLSEX common_controls{
        static_cast<DWORD>(sizeof(common_controls)), ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&common_controls);

    WNDCLASSEXW window_class{};
    window_class.cbSize = static_cast<UINT>(sizeof(window_class));
    window_class.hInstance = instance;
    window_class.lpfnWndProc = window_proc;
    window_class.lpszClassName = kWindowClassName;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (RegisterClassExW(&window_class) == 0U) {
        return 1;
    }

    AppState state;
    const HWND window = CreateWindowExW(0, kWindowClassName, kWindowTitle,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
        1120, 760, nullptr, nullptr, instance, &state);
    if (window == nullptr) {
        return 1;
    }
    ShowWindow(window, show_command);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    if (state.worker.joinable()) {
        state.worker.request_stop();
        state.worker.join();
    }
    return static_cast<int>(message.wParam);
}
