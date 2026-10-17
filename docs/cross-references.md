# Cross references

Phase 7 adds `tool xrefs <rom.gb>` and the GUI's **Xrefs** action. Locations in
ROM use a physical bank and CPU address, so two banks mapped at `$4000` remain
distinct. The analysis records:

- direct branch and call references from code to code
- absolute ROM memory accesses as code-to-data references
- low-confidence little-endian data-pointer candidates to known code starts
- references from code to RAM, hardware registers, and mapper control registers
- direct transfers between physical banks and calls between discovered functions

Each row includes the source, target, reference kind, confidence, and source
instruction. Hardware-register names are shown for common IO addresses. Data
pointer matches are candidates, not proof: arbitrary unknown bytes can match a
reachable code address.

The analyzer follows the current static bank assumption: `$0000`–`$3FFF` maps
to physical bank 0, and `$4000`–`$7FFF` uses the source bank (or bank 1 from
bank 0). It does not model mapper writes changing the active bank. Dynamic
`[HL]`, `[BC]`, `[DE]`, and `[C]` memory references are not assigned concrete
targets. These limits are carried forward to the memory-analysis phase.
