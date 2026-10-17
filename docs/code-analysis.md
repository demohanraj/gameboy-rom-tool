# Reachable code and data classification

Phase 4 adds `tool classify <rom.gb>`. It starts at the cartridge entry point
`$0100` and the five fixed interrupt vectors, then follows decoded
fall-through, direct branches, calls, and reset instructions. Conditional
branches explore both outcomes; calls explore the callee and the instruction
after the call. Returns, indirect jumps, HALT, STOP, and unknown control flow
stop that path.

Each output record has a physical bank, CPU address, ROM file offset, a
classification, confidence percentage, and the evidence used. Reachable legal
instructions become `CODE`; illegal, truncated, or overlapping candidates
remain `POSSIBLE_CODE`. The cartridge header bytes `$0104`–`$014F` are `DATA`.
Long uninterrupted runs of `$00` or `$FF` are weak `POSSIBLE_DATA` evidence.
Other bytes that are not reached remain `UNKNOWN`. Classification ranges are
coalesced where possible, while reachable instruction records retain their
decoded mnemonic and bytes.

These confidence scores are deterministic evidence weights, not statistical
probabilities. They do not account for runtime behavior, stack-derived targets,
pointer tables, or game-specific data formats. MBC register state is not
tracked: control flow into `$4000`–`$7FFF` stays in the source physical bank, or
assumes bank 1 when reached from bank 0. The classifier currently emits the
basic CODE, DATA, UNKNOWN, POSSIBLE_CODE, and POSSIBLE_DATA classes; jump tables,
pointer tables, graphics, text, audio, and compressed data are reserved for
later analysis.
