# moon-pe-inspect

A pure MoonBit PE/COFF inspector for build artifacts and security metadata.

`moon-pe-inspect` parses Windows PE files without loading or executing them. It
extracts PE32/PE32+ headers, sections, imports, exports, and hardening-related
metadata, then reports structural and security diagnostics. The core is a
bounds-checked MoonBit library; the CLI adds text and JSON output for CI and
analysis workflows.

## Why this project

PE files are produced by Windows build pipelines, shipped as DLLs and EXEs, and
examined during vulnerability triage. Existing generic binary readers stop at
byte access. This project owns the domain logic:

- validate DOS, PE, COFF, and optional-header structures;
- map RVAs to section file offsets;
- walk import descriptors and thunk tables;
- resolve export names, ordinals, and forwarders;
- detect missing hardening flags and writable-executable sections;
- return bounded errors instead of panicking on malformed input.

## Features

- PE32 and PE32+ support.
- Machine, subsystem, image base, entry point, checksum, and image-size metadata.
- Section table parsing with virtual/file ranges and characteristics.
- Imported DLL and function extraction, including ordinal imports.
- Export extraction with ordinal and forwarder resolution.
- Security diagnostics for ASLR, NX, CFG, high-entropy VA, RWX sections,
  executable entry points, and certificate-table presence.
- CLI commands with human-readable and JSON output.
- Reproducible synthetic PE fixtures for tests and demonstrations.

## Quick start

```bash
git clone https://github.com/404-32/byc001.git
cd byc001
moon test --target wasm
```

Inspect the included PE32 fixture:

```bash
moon run cmd/main -- inspect examples/minimal-pe32.exe
```

List imports and exports:

```bash
moon run cmd/main -- imports examples/minimal-pe32.exe
moon run cmd/main -- exports examples/minimal-pe32.exe
```

Produce JSON for CI:

```bash
moon run cmd/main -- inspect examples/minimal-pe32plus.exe --json
moon run cmd/main -- security examples/minimal-pe32plus.exe --json
```

Inspect a real Windows binary:

```bash
moon run cmd/main -- sections C:\Windows\System32\notepad.exe
```

## Library API

```moonbit nocheck
///|
let image = @pe.PEImage::parse(file_bytes)

///|
let sections = image.sections

///|
let imports = image.imports()

///|
let exports = image.exports()

///|
let diagnostics = image.security_diagnostics()

///|
let offset = image.rva_to_offset(0x1000UL)
```

Parsing is read-only. All binary reads are checked against the available byte
range, and malformed files produce a `PeError` containing a file offset and
message.

## Security checks

- `pe.no-aslr`: `DYNAMIC_BASE` is missing.
- `pe.no-nx`: `NX_COMPAT` is missing.
- `pe.no-cfg`: `GUARD_CF` is missing.
- `pe.no-high-entropy-va`: 64-bit image lacks high-entropy VA.
- `pe.rwx-section`: a section is writable and executable.
- `pe.entrypoint-not-executable`: entry point is outside executable sections.
- `pe.unsigned`: no certificate table is present.
- `pe.certificate-table`: certificate data exists, but the tool does not verify it.

The last distinction is intentional: detecting an Authenticode certificate table
is not the same as validating a signature.

## Scope

This project inspects static PE metadata. It does not load or execute images,
perform disassembly, unpack compressed binaries, validate certificate chains, or
parse every Windows-specific data directory. New formats and checks can be added
without changing the safe binary-reader foundation.

## Development

```bash
python scripts/generate_fixtures.py
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon fmt --check
moon run cmd/main -- inspect examples/minimal-pe32.exe
```

License: Apache-2.0.
