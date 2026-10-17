# Control-flow graphs

Phase 6 adds `tool cfg <rom.gb>`, which writes a Graphviz DOT graph with one
cluster per discovered function. Render it with Graphviz, for example:

```powershell
tool cfg game.gb > game-cfg.dot
dot -Tsvg game-cfg.dot -o game-cfg.svg
```

Each graph contains basic blocks, decoded instructions, and explicit edge
types: fallthrough, conditional true/false, unconditional branch, call,
return, and indirect flow. Conditional edges include taken/not-taken outcome
labels; the terminal instruction retains the actual condition such as `NZ` or
`C`. Calls have an edge to the discovered callee and a separate return
continuation edge. Conditional calls also retain their not-taken edge.

Graphs are intraprocedural. A direct call target links to the callee graph;
indirect jumps and calls have an explicit unknown-target node. Returns from a
function have terminal return edges. The graph does not guess indirect targets
or simplify branches. Physical-bank mapping follows the current static
assumption: a transfer into `$4000`–`$7FFF` from bank 0 uses physical bank 1,
and mapper register state is not modeled. The GUI's **CFG** action shows a
textual view; the CLI provides DOT for visualization.
