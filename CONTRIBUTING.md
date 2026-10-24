# Contributing

## Development requirements

- MoonBit toolchain compatible with the version used by CI.
- Python 3 for regenerating deterministic test fixtures.

## Validation

Run all checks before opening a pull request:

```bash
python scripts/generate_fixtures.py
moon fmt --check
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon package
```

The CI workflow also checks that fixture regeneration leaves the working tree
unchanged and exercises every CLI command against the synthetic PE samples.

## Code standards

- All binary reads in the core library must be bounds-checked.
- Parser loops and recursive directory walks must have explicit safety limits.
- Public APIs should return structured `PeError` values rather than panic.
- New directories should include malformed-input tests and safe demo fixtures.
- Keep the core package target-independent; CLI-only dependencies belong in the
  executable package.
- Source contributions are accepted under Apache-2.0.
