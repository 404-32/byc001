# Changelog

## 0.6.1 - 2026-10-26

- Tightened header-RVA, import, delay-import, and export directory bounds.
- Added full CLI JSON/SARIF contract verification.
- Corrected unsigned 32-bit checksum display.

## 0.6.0 - 2026-10-25

- Added PE Rich Header decoding.
- Added per-section Shannon entropy analysis and high-entropy diagnostics.
- Added Rich Header CLI/JSON output and deterministic fixture.

## 0.5.0 - 2026-10-25

- Added standalone COFF object parsing.
- Added COFF section and symbol-table support, long names, and auxiliary records.
- Added COFF CLI/JSON output and deterministic COFF fixture.

## 0.4.0 - 2026-10-24

- Added stored/computed PE checksum verification.
- Added CI-oriented `lint` security gate and SARIF 2.1.0 output.
- Added checksum mismatch diagnostics and artifact-diff coverage.

## 0.3.1 - 2026-10-24

- Added open-source compliance, security, design, contribution, and API docs.
- Added SPDX license identifiers to source files.
- Added CI packaging validation.

## 0.3.0 - 2026-10-24

- Added Bound Import, CLR/.NET header, certificate-record, and overlay parsing.
- Expanded security diagnostics and artifact diff coverage.

## 0.2.0 - 2026-10-23

- Added resource trees, base relocations, delay imports, TLS, Debug/PDB,
  Load Config, and exception directories.
- Added complete-directory CLI commands and tests.

## 0.1.0 - 2026-10-21

- Initial PE32/PE32+ parser, section and import/export inspection, security
  diagnostics, CLI, JSON output, fixtures, and CI.
