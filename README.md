# TOOL

TOOL is a C++20 Game Boy ROM analysis and decompilation project. Its goal is a
careful, behaviorally faithful reconstruction, with uncertainty made explicit.
It cannot recover the exact original source from an arbitrary compiled ROM.

The project is currently at **Phase 9**: it loads Game Boy ROMs, decodes SM83
instructions, emits bank-aware disassembly, and performs conservative
reachable-code analysis with confidence-rated CODE, DATA, POSSIBLE_CODE,
POSSIBLE_DATA, and UNKNOWN labels. It also discovers function entries and
direct call relationships, then builds per-function control-flow graphs and a
bank-aware cross-reference index for code, data, RAM, hardware registers,
mapper registers, banks, and functions. Data-pointer matches are candidates
because mapper state and data formats are not inferred yet. Phase 8 adds the
Game Boy address map, hardware-register metadata, and candidate discovery for
referenced ROM bytes, pointer tables, and printable text. Phase 9 adds a
structured opcode-level IR that carries bank-aware source locations, encoded
bytes, instruction effects, and CFG edges. CPU-state semantic lifting is still
a later phase. The last local validation built both frontends and passed all
58 CTest cases. A Tetris ROM smoke run produced 70 function entries, 548 basic
blocks, 2,051 decoded instructions, 869 CFG edges, and no decode failures; these
are static-analysis counts, not evidence of semantic equivalence.

## Build

Use CMake 3.20 or newer and a C++20 compiler:

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

The default test-enabled preset uses an installed GoogleTest package or fetches
GoogleTest v1.16.0 during configuration. The fetch requires network access. Set
`-DTOOL_FETCH_GTEST=OFF` to require a local package, or
`-DTOOL_BUILD_TESTS=OFF` for an application-only build. On Windows, the presets
use the Visual Studio 2022 x64 generator. To configure a release build, use the
`release` configure and build presets.

## CLI

```text
tool --help
tool --version
tool game.gb
tool analyze game.gb
tool disassemble game.gb
tool classify game.gb
tool functions game.gb
tool cfg game.gb
tool xrefs game.gb
tool memory game.gb
tool ir game.gb
```

The first two ROM forms report metadata and validation diagnostics.
`disassemble` prints candidate instructions for each physical ROM bank. Its
linear sweep can decode embedded data as instructions; code/data classification
is provided separately by `classify`, which follows the cartridge entry point,
interrupt vectors, direct branches/calls, and fall-through. Mapper state is not
modeled, and unreachable bytes generally remain UNKNOWN. `decompile` is not
implemented yet.

On Windows, the default build also creates a simple GUI demo:

```powershell
Set-Location "C:\Users\ADMIN\Desktop\Project Tool"
Start-Process -FilePath ".\build\Debug\tool-gui.exe" -WorkingDirectory "C:\Users\ADMIN\Desktop\Project Tool"
```

The demo opens a ROM, shows its metadata, and can run disassembly, code/data
classification, function discovery, CFG construction, cross-reference
analysis, memory/data reporting, or opcode-level IR with cancellation. Its
output preview is limited to 10,000 lines. This first demo uses native Windows
controls; the analysis remains in the shared core library. The full GUI is a
later roadmap phase.

## Project status

See [docs/architecture.md](docs/architecture.md) for module boundaries and
[docs/project-status.md](docs/project-status.md) for completed phases, remaining
work, and current limits. Commercial ROMs and other copyrighted binaries are
not included; only analyze software you have permission to inspect.
