# Intermediate representation

Phase 9 adds a structured, bank-aware opcode-level IR. Run it with
`tool ir game.gb`; the Windows GUI demo also has an **IR** action.

Each IR function contains basic blocks and explicit CFG successor edges. Each
decoded instruction records its physical ROM bank, CPU address, file offset,
primary and optional CB opcode, original bytes, instruction category, control
flow, cycles, flag read/write masks, memory read/write effects, and legality.
Decode failures are represented explicitly instead of being dropped.

This is an opcode-level IR, not yet a semantic lifting. The mnemonic and
operand strings are retained for display, while later passes can key off the
opcode and typed metadata. Phase 10 will expand opcodes into explicit CPU-state
operations, including register values, fixed-width arithmetic, flags, memory
accesses, and stack behavior. No C reconstruction or semantic-equivalence
claim is made at this phase.

The module preserves CFG branch, call, return, and indirect edges and exposes
counts for functions, blocks, instructions, edges, and decode failures. Mapper
state limitations from earlier analysis phases still apply.
