# Project status and roadmap

TOOL is a phased C++20 Game Boy ROM analysis project. Its core engine is
separate from the CLI and the current native Windows GUI demo. This source
snapshot ends at Phase 9; it is not yet a complete decompiler.

## Completed phases

| Phase | Scope | Implemented result |
|---|---|---|
| 0 | Build foundation | CMake, core library, CLI, logging, and GoogleTest setup |
| 1 | ROM and cartridge model | Header diagnostics, cartridge identification, physical banks, address translation |
| 2 | SM83 decoder | Base and CB opcode metadata with lengths, cycles, flags, memory effects, and flow |
| 3 | Disassembler | Linear physical-bank listing with CPU addresses and ROM offsets |
| 4 | Reachability | Evidence-based code/data classification with confidence labels |
| 5 | Function discovery | Reset, interrupt, direct-call, and RST entry candidates with caller/callee links |
| 6 | Control-flow graphs | Per-function blocks and typed CFG edges; DOT output |
| 7 | Cross references | Code/data, bank, function, memory, hardware, and mapper reference index |
| 8 | Memory/data analysis | Formal address map, register metadata, referenced-ROM, pointer-table, and text candidates |
| 9 | Intermediate representation | Bank-aware opcode-level IR preserving encodings, effects, cycles, and CFG edges |

The current Windows build passed all 58 CTest cases. The Tetris ROM smoke run
completed with 70 discovered functions, 548 blocks, 2,051 decoded instructions,
869 CFG edges, and no decode failures. Those counts describe static-analysis
output for that ROM; they do not demonstrate semantic or behavioral
equivalence.

## Remaining phases

| Phase | Planned scope |
|---|---|
| 10 | CPU semantic lifting into explicit register, flag, arithmetic, memory, and stack operations |
| 11 | SSA and data-flow analysis |
| 12 | Variable and type inference |
| 13 | Control-flow structuring |
| 14 | C abstract syntax tree |
| 15 | C code generation |
| 16 | Game Boy support runtime for generated code |
| 17 | Behavioral verification and state comparison |
| 18 | Full GUI application |
| 19 | Assisted semantic naming |
| 20 | Optimization and advanced analysis |

Each phase needs focused tests, stable interfaces, and documented uncertainty
before later phases depend on it. C generation should wait until IR semantics
and data-flow are stable. Behavioral verification should only be claimed after
reference execution, generated execution, and state comparison exist.

## Current boundaries

- The current IR is opcode-level; it does not express each instruction as
  explicit CPU-state transitions.
- Mapper state and dynamic execution are not modeled. Some switchable-bank
  decisions use a documented default-bank assumption.
- Data pointers, tables, and printable strings are tentative candidates.
- Variable/type recovery, C generation, the generated runtime, and behavioral
  verification are not implemented.
- A basic Windows GUI demo exists. The full GUI remains Phase 18.
- No redistribution or modification license has been selected; see
  [LICENSE](../LICENSE).
