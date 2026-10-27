# Contributing

## Development requirements

- MoonBit toolchain compatible with the version used by CI.
- Python 3 for regenerating deterministic test fixtures.

## Validation

Run all checks before opening a pull request:

```bash
python scripts/generate_fixtures.py
moon fmt --check
moon check --target all --deny-warn
moon test --target wasm --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon test --package 404-32/moon-pe-inspect --target native --deny-warn
moon coverage analyze -p 404-32/moon-pe-inspect -- -f summary > /tmp/coverage.txt
python scripts/check_coverage.py /tmp/coverage.txt
moon package
python scripts/verify_cli.py
```

The CI workflow also checks that fixture regeneration leaves the working tree
unchanged, exercises every CLI command against the synthetic PE samples, and
packages the module.

## Code standards

- All binary reads in the core library must be bounds-checked.
- Parser loops and recursive directory walks must have explicit safety limits.
- Public APIs should return structured `PeError` values rather than panic.
- New directories should include malformed-input tests and safe demo fixtures.
- Security rules require an isolated positive and negative matrix case.
- Parser changes must retain the truncation and deterministic mutation tests.
- Keep the core package target-independent; CLI-only dependencies belong in the
  executable package.
- Source contributions are accepted under Apache-2.0.
