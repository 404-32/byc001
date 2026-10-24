# API guide

## Parse

```moonbit
let image = @pe.PEImage::parse(file_bytes)
```

The input is a `Bytes` value. Parsing validates the outer PE structures and
returns `PeError(offset, message)` for malformed input.

## Core metadata

```moonbit
let offset = image.rva_to_offset(0x1000UL)
let section = image.section_by_name(".text")
let imports = image.imports()
let exports = image.exports()
let directories = image.directories
```

## Extended directories

```moonbit
let resources = image.resources()
let relocations = image.base_relocations()
let delay_imports = image.delay_imports()
let tls = image.tls()
let debug = image.debug_entries()
let load_config = image.load_config()
let exceptions = image.exception_entries()
let bound_imports = image.bound_imports()
let clr = image.clr_header()
let certificates = image.certificates()
let overlay = image.overlay()
let checksum = image.checksum_info()
```

Optional directories return an empty array or `None` when absent. Malformed
present directories return `PeError`.

## Analysis

```moonbit
let diagnostics = image.security_diagnostics()
let changes = image.diff(other_image)
```

Security diagnostics are advisory. Certificate and CLR findings describe present
metadata and do not establish trust.

`checksum_info()` reports the stored value, computed value, whether a checksum was
present, and whether it is valid.

## CLI

Run `moon run cmd/main -- --help` for the complete command list. Every metadata
command accepts `--json`, and `diff` accepts two PE paths.
`security` also accepts `--sarif`, while `lint` provides a CI gate with JSON or
SARIF output.
