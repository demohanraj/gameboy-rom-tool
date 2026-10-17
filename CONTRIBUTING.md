# Contributing

Changes should follow the project's phase gates: establish tests for a phase,
implement that phase, build it, run its tests, and document known limits before
starting the next major subsystem.

## Development checks

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Keep the core independent of Qt and Python. Treat ROM data as untrusted input,
preserve uncertainty in analysis results, and do not describe reconstruction as
recovery of the original source. Do not add copyrighted commercial ROMs to the
repository.

## License

The project license has not yet been selected. Confirm the intended license
before redistributing contributions.
