# Design and safety model

## Layers

1. **Binary primitives** (`binary.mbt`) provide checked little-endian reads and
   bounded ASCII decoding.
2. **PE core** (`parser.mbt`) validates DOS, PE, COFF, optional-header, section,
   and data-directory boundaries.
3. **Directory parsers** interpret imports, exports, resources, relocations,
   delay imports, TLS, Debug, Load Config, exceptions, Bound Imports, CLR, and
   certificates.
4. **Analysis** combines parsed metadata into security diagnostics and artifact
   diffs.
5. **CLI** performs file I/O and renders text or JSON without duplicating parser
   policy.

## Safety invariants

- No read occurs outside the supplied byte buffer.
- RVAs must map into initialized bytes of a section.
- Section counts, imports, exports, resources, and relocation blocks have finite
  safety limits.
- Certificate-table offsets are treated as file offsets, not RVAs.
- CLR and Load Config fields are read only when the declared structure is large
  enough.
- Parsing is read-only and never loads or executes an inspected image.

## Error model

Recoverable parse failures raise `PeError(offset, message)`. The offset points to
the file location associated with the failing header, directory, or read. Core
analysis methods catch optional-directory errors where a complete result can
still be produced.

## Compatibility boundary

The project inspects PE32 and PE32+ images on any host through Wasm. It does not
perform disassembly, execution, signature-chain validation, decompression, or
resource payload interpretation.
