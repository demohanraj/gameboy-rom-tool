# Verification status

Behavioral verification is not implemented. It must not be claimed until the
project can execute a trusted reference model and the generated reconstruction
and compare their observable states. Future reports should state which inputs
and paths were checked; test percentages are evidence summaries, not proofs of
equivalence.

The current test suite covers the CLI, logging, ROM-header parsing, cartridge
identification, file validation, checksums, bank translation, all 256 base plus
256 CB-prefixed opcode entries, and disassembly bank/address/offset mapping,
byte coverage, and truncated instructions. Reachability tests cover reset and
interrupt seeds, direct branches and calls, known header data, uncertain fill
runs, unknown regions, and overlapping instruction candidates. These tests
validate component behavior; they are not CPU execution or
behavioral-equivalence checks.
