# Limitations and claims

Compiled ROMs generally do not retain original source names, comments,
structures, macros, formatting, or all type information. TOOL therefore aims
for a behaviorally faithful reconstruction; it cannot promise the exact
original C source.

Phase 4 adds static reachable-code analysis. It seeds the cartridge entry
point and fixed interrupt vectors, follows decoded direct control flow, marks
the cartridge header as data, and treats long runs of 00/FF bytes as weak
possible-data evidence. It does not model MBC writes, indirect jumps, pointer
tables, strings, graphics formats, compressed data, or runtime traces. A
switchable-bank target assumes the current physical bank, or bank 1 when
entered from fixed bank 0. Unreached bytes remain UNKNOWN; reachable illegal or
overlapping instruction candidates remain POSSIBLE_CODE. Confidence scores
summarize these static assumptions and are not probabilities of correctness.

The tool does not execute instructions, generate C, or perform behavioral
verification. The eleven undocumented base opcodes are marked illegal with
unknown behavior. Metadata and static analysis do not establish that a ROM will
run correctly or that later reconstructed code is equivalent. No equivalence
claims are produced.
