# Physical-bank disassembly

Phase 3 adds `tool disassemble <rom.gb>`. It walks the ROM's bytes from start to
end, decoding one SM83 instruction at a time within each physical ROM bank. For
each entry it reports:

- physical bank number;
- CPU address within that bank's address window;
- absolute ROM file offset;
- instruction bytes and decoded mnemonic/operands.

Bank 0 uses CPU addresses `$0000`–`$3FFF`; later physical banks use
`$4000`–`$7FFF`. The same CPU address can occur in many banks, so the bank and
file offset are needed to identify the source bytes. Output is streamed one
entry at a time, so disassembly does not construct a second expanded copy of a
large ROM in memory.

This is a physical-bank linear sweep, not control-flow analysis. It starts at
the first byte of every bank and decodes every byte sequence it can. Data
tables, graphics, padding, and unreachable bytes can therefore appear as
instructions. Undocumented opcodes remain visible and are marked; if the final
bytes of a truncated bank cannot complete an instruction, the disassembler
emits a `.DB` entry for the byte and records the decode error. The separate
Phase 4 `tool classify` command performs reachability-based classification; see
[code-analysis.md](code-analysis.md).
