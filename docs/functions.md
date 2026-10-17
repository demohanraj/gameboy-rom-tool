# Function discovery

Phase 5 adds `tool functions <rom.gb>` and a **Functions** action in the
Windows demo. Discovery seeds the cartridge entry at `$0100` and the five
fixed interrupt vectors. It walks reachable intra-function control flow and
creates separate entries for direct `CALL`, conditional `CALL`, and `RST`
targets. It records direct caller and callee IDs.

Each function has a stable ID containing its physical bank and CPU address,
such as `fn_b0000_0160`. Generated names use `entry_0100` for the reset entry,
`irq_vblank` and related names for interrupt vectors, and `sub_0160` or a
bank-qualified name for direct call targets. Confidence is an evidence weight,
not a probability.

This phase does not infer complete function boundaries, parameter or return
values, indirect-call targets, jump-table entries, or dynamic behavior. The
reachable instructions attributed to a function are those found by following
branches and fall-through while treating direct calls as separate entries.
The call graph contains direct CALL/RST edges only. A switchable-window target
from fixed bank 0 assumes physical bank 1; mapper register state is not tracked.
CFGs and richer cross references are later phases.
