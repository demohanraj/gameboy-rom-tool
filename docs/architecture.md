# Architecture and phase plan

The engine is the product; graphical frontends are optional. The `tool_core`
library contains reusable application-facing logic and has no UI dependency.
The CLI and the current native Windows GUI demo depend on that library. A
future Qt 6 Widgets frontend can use the same public interfaces rather than
embedding analysis logic in widgets.

```text
CLI ──────────┐
              ├── Application / analysis pipeline ── ROM, CPU, hardware
Windows demo ─┘                                      │
                                                    ▼
                 disassembly → functions → CFG → IR → analysis → C export → verification
```

## Current milestone

Phase 0 established the CMake project, a core library, structured logging,
CLI argument handling, and GoogleTest-based test cases. Phase 1 added immutable
ROM loading, cartridge-header parsing and validation, cartridge type
identification, size/checksum diagnostics, physical ROM banks, and explicit
CPU-address-to-file-offset translation. Phase 2 added a structured SM83
instruction decoder and metadata for all base and CB-prefixed opcodes,
including cycles, flags, control flow, and data-memory effects. Phase 3 adds
physical-bank linear disassembly with bank, CPU address, ROM file offset, and
instruction bytes. Phase 4 adds reachable-code analysis and confidence-rated
region labels. Phase 5 discovers reset and interrupt entries, direct CALL/RST
targets, and their direct caller/callee relationships. Phase 6 builds
per-function basic-block graphs with explicit typed edges and Graphviz DOT
output. Phase 7 indexes code, data-pointer candidates, RAM, hardware and mapper
register, physical-bank, and function references. Mapper state and dynamic
execution are not modeled. Phase 8 adds a formal address-space map, hardware
register metadata, and tentative discovery of directly referenced ROM data,
pointer tables, and printable strings. Phase 9 adds a typed, bank-aware
opcode-level IR that preserves instruction encodings, decoder effects, CFG
blocks, and edges; it does not yet lift instructions into CPU-state semantics.

## Planned phases

1–2. ROM/cartridge metadata and complete SM83 instruction decoding are implemented.
3. Physical-bank linear disassembly that preserves CPU address, bank, ROM offset, and bytes. Implemented; see [disassembly.md](disassembly.md).
4. Reachability-based code/data classification with confidence. Implemented; see [code-analysis.md](code-analysis.md).
5. Function entry and direct call discovery. Implemented; see [functions.md](functions.md).
6. CFG recovery for discovered functions. Implemented; see [cfg.md](cfg.md).
7. Cross-reference analysis. Implemented; see [cross-references.md](cross-references.md).
8. Memory and data analysis. Implemented; see [memory-data.md](memory-data.md).
9. Structured opcode-level IR. Implemented; see [ir.md](ir.md).
10–16. CPU semantics, data flow, type recovery, control-flow structuring,
      C generation, and a Game Boy runtime.
17. Behavioral verification with explicit evidence and uncertainty.
18+. Qt GUI, assisted naming, and deeper analysis. A basic Windows GUI demo is
     available before this phase; it is not the complete planned GUI.

Each phase needs tests before later phases depend on it. The C reconstruction
must retain hardware and CPU semantics and must not imply that original names,
comments, or source constructs were recovered.
