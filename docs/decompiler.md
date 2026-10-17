# Decompiler status

The decompilation pipeline is not implemented yet. It will be built only after
instruction decoding, control-flow recovery, and the intermediate
representation have stable semantics and tests.

The intended output is conservative C reconstruction. Unknown names and
relationships should remain explicit (for example, address-derived variable
names), and unsupported behavior must be reported rather than guessed.
