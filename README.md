# moon-pe-inspect

[![CI](https://github.com/404-32/byc001/actions/workflows/ci.yml/badge.svg)](https://github.com/404-32/byc001/actions/workflows/ci.yml)

A pure MoonBit PE/COFF inspector for build artifacts and security metadata.

`moon-pe-inspect` parses Windows PE files without loading or executing them. It
extracts PE32/PE32+ headers, sections, imports, exports, resources, relocations,
delay imports, TLS, Debug/PDB metadata, Load Config, and exception tables. The
core is a bounds-checked MoonBit library; the CLI adds text, JSON, and artifact
diff output for CI and analysis workflows.

It also parses standalone COFF object files, including section tables, symbol
records, long symbol names, string tables, and auxiliary-symbol skipping.

## Why this project

PE files are produced by Windows build pipelines, shipped as DLLs and EXEs, and
examined during vulnerability triage. Existing generic binary readers stop at
byte access. This project owns the domain logic:

- validate DOS, PE, COFF, and optional-header structures;
- map RVAs to section file offsets;
- walk import descriptors and thunk tables;
- resolve export names, ordinals, and forwarders;
- traverse resource, relocation, delay-import, TLS, debug, load-config, and
  exception directories;
- detect missing hardening flags and writable-executable sections;
- compare build artifacts and report metadata changes;
- return bounded errors instead of panicking on malformed input.

## Features

- PE32 and PE32+ support.
- Machine, subsystem, image base, entry point, checksum, and image-size metadata.
- Section table parsing with virtual/file ranges and characteristics.
- Imported DLL and function extraction, including ordinal imports.
- Export extraction with ordinal and forwarder resolution.
- Resource trees, base relocations, delay imports, TLS callbacks, CodeView PDB
  metadata, Load Config, and exception entries.
- Bound-import descriptors, CLR/.NET headers, Authenticode certificate records,
  and overlay detection.
- Standalone COFF object parsing with symbols and string tables.
- Rich Header decoding and per-section Shannon entropy analysis.
- Security diagnostics for ASLR, NX, CFG metadata, SafeSEH, security cookies,
  high-entropy VA, RWX sections, relocations, executable entry points, and
  certificate-table presence.
- PE checksum calculation and stored-checksum validation.
- Artifact diffing for headers, sections, imports, exports, directories, and
  security findings.
- CI security gate and SARIF 2.1.0 output.
- CLI commands with human-readable and JSON output.
- Reproducible synthetic PE fixtures for tests and demonstrations.

## Quick start

Install from mooncakes.io:

```bash
moon add 404-32/moon-pe-inspect@0.6.0
```

Package page:
https://mooncakes.io/docs/404-32/moon-pe-inspect/0.6.0

Build and test from source:

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

Inspect extended directories and compare two artifacts:

```bash
moon run cmd/main -- directories examples/minimal-pe32.exe
moon run cmd/main -- resources examples/minimal-pe32.exe
moon run cmd/main -- delay-imports examples/minimal-pe32.exe
moon run cmd/main -- load-config examples/minimal-pe32.exe
moon run cmd/main -- bound-imports examples/minimal-pe32.exe
moon run cmd/main -- clr examples/minimal-pe32.exe
moon run cmd/main -- certificates examples/minimal-pe32.exe
moon run cmd/main -- overlay examples/minimal-pe32.exe
moon run cmd/main -- checksum examples/minimal-pe32.exe
moon run cmd/main -- rich examples/rich-pe32.exe
moon run cmd/main -- diff examples/minimal-pe32.exe examples/minimal-pe32plus.exe
moon run cmd/main -- coff examples/minimal-coff.obj
```

Use the security gate or SARIF output in CI:

```bash
moon run cmd/main -- lint examples/minimal-pe32.exe --json
moon run cmd/main -- security examples/minimal-pe32.exe --sarif
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
let resources = image.resources()

///|
let relocations = image.base_relocations()

///|
let delay_imports = image.delay_imports()

///|
let tls = image.tls()

///|
let debug_entries = image.debug_entries()

///|
let load_config = image.load_config()

///|
let exceptions = image.exception_entries()

///|
let bound_imports = image.bound_imports()

///|
let clr_header = image.clr_header()

///|
let certificates = image.certificates()

///|
let overlay = image.overlay()

///|
let checksum = image.checksum_info()

///|
let rich = image.rich_header()

///|
let entropies = image.section_entropies()

///|
let diagnostics = image.security_diagnostics()

///|
let offset = image.rva_to_offset(0x1000UL)

///|
let object = @pe.CoffObject::parse(coff_bytes)
```

Parsing is read-only. All binary reads are checked against the available byte
range, and malformed files produce a `PeError` containing a file offset and
message.

## Security checks

- `pe.no-aslr`: `DYNAMIC_BASE` is missing.
- `pe.no-nx`: `NX_COMPAT` is missing.
- `pe.no-cfg`: `GUARD_CF` is missing.
- `pe.cfg-metadata-missing`: CFG is advertised without a guard function table.
- `pe.aslr-without-relocations`: ASLR is advertised without base relocations.
- `pe.no-safeseh`: 32-bit image has no SafeSEH metadata or `NO_SEH`.
- `pe.no-security-cookie`: Load Config does not declare a `/GS` cookie.
- `pe.no-high-entropy-va`: 64-bit image lacks high-entropy VA.
- `pe.rwx-section`: a section is writable and executable.
- `pe.entrypoint-not-executable`: entry point is outside executable sections.
- `pe.unsigned`: no certificate table is present.
- `pe.certificate-table`: certificate data exists, but the tool does not verify it.
- `pe.checksum-mismatch`: the stored PE checksum does not match the file.
- `pe.high-entropy-section`: a section has entropy of at least 7.5.

The last distinction is intentional: detecting an Authenticode certificate table
is not the same as validating a signature.

## Scope

This project inspects static PE metadata. It does not load or execute images,
perform disassembly, unpack compressed binaries, validate certificate chains, or
parse every Windows-specific data directory. New formats and checks can be added
without changing the safe binary-reader foundation.

## MoonBit ecosystem fit

- Publishable MoonBit module with a stable `moon add` entry point.
- Pure MoonBit parsing core with bounded reads and no unsafe native dependency.
- Wasm-first execution for cross-platform use in CI.
- Library, CLI, JSON, examples, and generated public interfaces live together.
- Official `moonbitlang/async` is used only by the CLI file-I/O layer.

## References

- Microsoft PE Format:
  https://learn.microsoft.com/windows/win32/debug/pe-format
- Apache License 2.0:
  https://www.apache.org/licenses/LICENSE-2.0

The implementation is original code derived from the public format
specification. It does not vendor or copy existing parser implementations.

## License and security

The project is licensed under Apache-2.0. See `SECURITY.md` for the trusted-input
model and vulnerability reporting guidance, and `THIRD_PARTY_NOTICES.md` for the
runtime dependency notice.

## Development

```bash
python scripts/generate_fixtures.py
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon fmt --check
moon package
moon run cmd/main -- inspect examples/minimal-pe32.exe
```

License: Apache-2.0.
