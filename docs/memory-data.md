# Memory map and data candidates

Phase 8 adds `tool memory <rom.gb>` and the GUI's **Memory** action. The core
maps all CPU address ranges, records echo-RAM aliases, keeps switchable banks
explicit, and includes metadata for common DMG/CGB hardware registers. The ROM
header's CGB flag distinguishes DMG-only, CGB-only, and compatible/unknown
hardware mode.

The data pass reports absolute ROM locations referenced by reachable code,
groups adjacent aligned code-pointer matches as pointer-table candidates, and
finds printable ASCII strings outside classified instruction bytes. Each result
has a confidence score and is labeled as a candidate where interpretation is
uncertain. It does not infer general-purpose numeric tables, graphics, audio,
or compressed data yet.

Mapper register state is not simulated. The displayed bank selections are
static assumptions, and CGB-compatible ROMs do not prove which hardware mode
was used at runtime. I/O registers are modeled separately from ordinary RAM;
their metadata records access permissions and known side effects.
