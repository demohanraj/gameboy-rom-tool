# Game Boy platform model

Phase 1 implements ROM loading, cartridge-header parsing, supported cartridge
identification, and physical ROM banks. Phase 2 adds an SM83 decoder with
instruction length, T-state timing, flag effects, control-flow type, and
data-memory access metadata. Phase 3 linearly decodes each physical bank while
preserving CPU addresses and ROM file offsets. Phase 4 follows the cartridge
entry point and interrupt vectors through direct control flow, then labels
reachable instructions and known or uncertain regions. It does not model MBC
register writes, so switchable-bank targets use an explicit bank assumption.
Bank-aware translation preserves the distinction between CPU addresses,
cartridge banks, and file offsets. The decoder describes instructions but does
not execute them.

ROM bytes are untrusted data. The application must never execute them as host
code. The first implementation will prioritize DMG-compatible behavior while
leaving room for CGB banking and hardware extensions.
