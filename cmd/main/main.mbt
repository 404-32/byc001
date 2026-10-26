// SPDX-License-Identifier: Apache-2.0

///|
const VERSION : String = "0.6.1"

///|
const USAGE : String =
  #|moon-pe-inspect - PE/COFF binary inspection and security audit
  #|
  #|Usage:
  #|  moon-pe-inspect inspect  <file.exe|file.dll> [--json]
  #|  moon-pe-inspect sections <file> [--json]
  #|  moon-pe-inspect imports  <file> [--json]
  #|  moon-pe-inspect exports  <file> [--json]
  #|  moon-pe-inspect security <file> [--json]
  #|  moon-pe-inspect directories <file> [--json]
  #|  moon-pe-inspect resources <file> [--json]
  #|  moon-pe-inspect relocations <file> [--json]
  #|  moon-pe-inspect delay-imports <file> [--json]
  #|  moon-pe-inspect tls <file> [--json]
  #|  moon-pe-inspect debug <file> [--json]
  #|  moon-pe-inspect load-config <file> [--json]
  #|  moon-pe-inspect exceptions <file> [--json]
  #|  moon-pe-inspect bound-imports <file> [--json]
  #|  moon-pe-inspect clr <file> [--json]
  #|  moon-pe-inspect certificates <file> [--json]
  #|  moon-pe-inspect overlay <file> [--json]
  #|  moon-pe-inspect checksum <file> [--json]
  #|  moon-pe-inspect rich <file> [--json]
  #|  moon-pe-inspect coff <file.obj> [--json]
  #|  moon-pe-inspect lint <file> [--json|--sarif]
  #|  moon-pe-inspect diff <left> <right> [--json]

///|
async fn main {
  let raw_args = @env.args()
  let args = []
  let mut index = 1
  while index < raw_args.length() {
    args.push(raw_args[index])
    index = index + 1
  }
  if args.is_empty() {
    println(USAGE)
    return
  }
  if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
    println(USAGE)
    return
  }
  if args[0] == "version" || args[0] == "--version" || args[0] == "-V" {
    println("moon-pe-inspect \{VERSION}")
    return
  }
  let command = args[0]
  let positionals = []
  let mut json_mode = false
  let mut sarif_mode = false
  for arg_index in 1..<args.length() {
    if args[arg_index] == "--json" {
      json_mode = true
    } else if args[arg_index] == "--sarif" {
      sarif_mode = true
    } else {
      positionals.push(args[arg_index])
    }
  }
  if sarif_mode && command != "security" && command != "lint" {
    println("--sarif is only supported by security and lint")
    abort("unsupported output format")
  }
  if command == "diff" {
    if positionals.length() != 2 {
      println(USAGE)
      abort("diff requires two PE files")
    }
    diff_files(positionals[0], positionals[1], json_mode)
    return
  }
  if positionals.length() != 1 {
    println(USAGE)
    abort("expected exactly one PE file")
  }
  if command == "coff" {
    show_coff(load_coff(positionals[0]), json_mode)
    return
  }
  let image = load_image(positionals[0])
  match command {
    "inspect" => inspect(image, json_mode)
    "sections" => sections(image, json_mode)
    "imports" => imports(image, json_mode)
    "exports" => exports(image, json_mode)
    "security" =>
      if sarif_mode {
        security_sarif(image, positionals[0])
      } else {
        security(image, json_mode)
      }
    "directories" => directories(image, json_mode)
    "resources" => resources(image, json_mode)
    "relocations" => relocations(image, json_mode)
    "delay-imports" => delay_imports(image, json_mode)
    "tls" => tls(image, json_mode)
    "debug" => debug(image, json_mode)
    "load-config" => load_config(image, json_mode)
    "exceptions" => exceptions(image, json_mode)
    "bound-imports" => bound_imports(image, json_mode)
    "clr" => clr(image, json_mode)
    "certificates" => certificates(image, json_mode)
    "overlay" => overlay(image, json_mode)
    "checksum" => checksum(image, json_mode)
    "rich" => rich(image, json_mode)
    "lint" => lint(image, positionals[0], json_mode, sarif_mode)
    _ => {
      println("unknown command: \{command}")
      println(USAGE)
      abort("unknown command")
    }
  }
}

///|
async fn load_image(path : String) -> @pe.PEImage {
  let bytes = load_bytes(path)
  @pe.PEImage::parse(bytes) catch {
    @pe.PeError(offset, message) => {
      println("invalid PE file: offset=\{offset}: \{message}")
      abort("PE parse failed")
    }
  }
}

///|
async fn load_bytes(path : String) -> Bytes {
  let file = @fs.open(path, mode=ReadOnly) catch {
    error => {
      println("failed to open \{path}: \{error}")
      abort("file read failed")
    }
  }
  defer file.close()
  let size = file.size()
  if size < 0L || size > 0x7fffffffL {
    println("file is too large for this tool")
    abort("file size limit exceeded")
  }
  let bytes = file.read_exactly(size.to_int()) catch {
    error => {
      println("failed to read \{path}: \{error}")
      abort("file read failed")
    }
  }
  bytes
}

///|
async fn load_coff(path : String) -> @pe.CoffObject {
  let bytes = load_bytes(path)
  @pe.CoffObject::parse(bytes) catch {
    @pe.PeError(offset, message) => {
      println("invalid COFF object: offset=\{offset}: \{message}")
      abort("COFF parse failed")
    }
  }
}

///|
fn show_coff(object : @pe.CoffObject, json_mode : Bool) -> Unit {
  if json_mode {
    println(coff_json(object))
    return
  }
  println("machine: \{@pe.architecture_name(object.machine)}")
  println("sections: \{object.section_count}")
  println("symbols: \{object.symbols.length()}")
  for section in object.sections {
    println(
      "\{section.name}: raw=\{hex(section.raw_offset.to_uint64())}/\{section.raw_size} flags=\{hex(section.characteristics)}",
    )
  }
  for symbol in object.symbols {
    println(
      "symbol \{symbol.name}: section=\{symbol.section_number} value=\{hex(symbol.value)} class=\{symbol.storage_class}",
    )
  }
}

///|
fn coff_json(object : @pe.CoffObject) -> String {
  let builder = StringBuilder()
  builder.write_string("{\"machine\":")
  write_json_string(builder, @pe.architecture_name(object.machine))
  builder.write_string(",\"timestamp\":")
  builder.write_string(object.timestamp.to_string())
  builder.write_string(",\"characteristics\":")
  builder.write_string(object.characteristics.to_string())
  builder.write_string(",\"sections\":[")
  let mut first_section = true
  for section in object.sections {
    if !first_section {
      builder.write_char(',')
    }
    first_section = false
    builder.write_string("{\"name\":")
    write_json_string(builder, section.name)
    builder.write_string(",\"rawOffset\":")
    write_json_string(builder, hex(section.raw_offset.to_uint64()))
    builder.write_string(",\"rawSize\":")
    builder.write_string(section.raw_size.to_string())
    builder.write_string(",\"characteristics\":")
    write_json_string(builder, hex(section.characteristics))
    builder.write_char('}')
  }
  builder.write_string("],\"symbols\":[")
  let mut first_symbol = true
  for symbol in object.symbols {
    if !first_symbol {
      builder.write_char(',')
    }
    first_symbol = false
    builder.write_string("{\"name\":")
    write_json_string(builder, symbol.name)
    builder.write_string(",\"section\":")
    builder.write_string(symbol.section_number.to_string())
    builder.write_string(",\"value\":")
    write_json_string(builder, hex(symbol.value))
    builder.write_string(",\"storageClass\":")
    builder.write_string(symbol.storage_class.to_string())
    builder.write_char('}')
  }
  builder.write_string("]}")
  builder.to_string()
}

///|
fn inspect(image : @pe.PEImage, json_mode : Bool) -> Unit {
  if json_mode {
    println(inspect_json(image))
    return
  }
  println("format: \{format_name(image.format)}")
  println(
    "machine: \{@pe.architecture_name(image.machine)} (\{hex(image.machine.to_uint64())})",
  )
  println("subsystem: \{@pe.subsystem_name(image.subsystem)}")
  println("image base: \{hex(image.image_base)}")
  println("entry point: \{hex(image.entry_point)}")
  println("image size: \{image.size_of_image}")
  println("sections: \{image.number_of_sections}")
  let directories = []
  for directory in image.directories {
    if directory.virtual_address != 0UL || directory.size != 0 {
      directories.push(directory.name)
    }
  }
  println("directories: \{directories.join(",")}")
  match image.overlay() {
    Some(overlay) =>
      println(
        "overlay: offset=\{hex(overlay.offset.to_uint64())} size=\{overlay.size}",
      )
    None => ()
  }
  let diagnostics = image.security_diagnostics()
  println("security diagnostics: \{diagnostics.length()}")
  for diagnostic in diagnostics {
    println(
      "  [\{severity_name(diagnostic.severity)}] \{diagnostic.code}: \{diagnostic.message}",
    )
  }
}

///|
fn sections(image : @pe.PEImage, json_mode : Bool) -> Unit {
  if json_mode {
    println(sections_json(image))
    return
  }
  let entropies = image.section_entropies() catch { @pe.PeError(_, _) => [] }
  for index in 0..<image.sections.length() {
    let section = image.sections[index]
    if entropies.length() == image.sections.length() {
      println(
        "\{section.name}: va=\{hex(section.virtual_address)} vsize=\{section.virtual_size} raw=\{hex(section.raw_offset.to_uint64())}/\{section.raw_size} entropy=\{entropies[index].entropy} flags=\{hex(section.characteristics)}",
      )
    } else {
      println(
        "\{section.name}: va=\{hex(section.virtual_address)} vsize=\{section.virtual_size} raw=\{hex(section.raw_offset.to_uint64())}/\{section.raw_size} flags=\{hex(section.characteristics)}",
      )
    }
  }
}

///|
fn imports(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let libraries = image.imports() catch {
    @pe.PeError(offset, message) => {
      println("invalid import table: offset=\{offset}: \{message}")
      abort("import parse failed")
    }
  }
  if json_mode {
    println(imports_json(libraries))
    return
  }
  for library in libraries {
    println(library.name)
    for symbol in library.symbols {
      match symbol.name {
        Some(name) => println("  \{name}")
        None => println("  #\{symbol.ordinal.unwrap()}")
      }
    }
  }
}

///|
fn exports(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let symbols = image.exports() catch {
    @pe.PeError(offset, message) => {
      println("invalid export table: offset=\{offset}: \{message}")
      abort("export parse failed")
    }
  }
  if json_mode {
    println(exports_json(symbols))
    return
  }
  for symbol in symbols {
    match symbol.forwarder {
      Some(target) =>
        println("\{symbol.name} -> \{target} (ordinal \{symbol.ordinal})")
      None =>
        println(
          "\{symbol.name}: rva=\{hex(symbol.rva)} ordinal=\{symbol.ordinal}",
        )
    }
  }
}

///|
fn security(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let diagnostics = image.security_diagnostics()
  if json_mode {
    println(diagnostics_json(diagnostics))
    return
  }
  for diagnostic in diagnostics {
    println(
      "[\{severity_name(diagnostic.severity)}] \{diagnostic.code}: \{diagnostic.message}",
    )
  }
}

///|
fn directories(image : @pe.PEImage, json_mode : Bool) -> Unit {
  if json_mode {
    println(directories_json(image))
    return
  }
  for directory in image.directories {
    if directory.virtual_address != 0UL || directory.size != 0 {
      println(
        "\{directory.index} \{directory.name}: rva=\{hex(directory.virtual_address)} size=\{directory.size}",
      )
    }
  }
}

///|
fn resources(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let entries = image.resources() catch {
    @pe.PeError(offset, message) => {
      println("invalid resource directory: offset=\{offset}: \{message}")
      abort("resource parse failed")
    }
  }
  if json_mode {
    println(resources_json(entries))
    return
  }
  for entry in entries {
    println(
      "\{entry.path}: rva=\{hex(entry.data_rva)} size=\{entry.size} code-page=\{entry.code_page}",
    )
  }
}

///|
fn relocations(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let blocks = image.base_relocations() catch {
    @pe.PeError(offset, message) => {
      println("invalid relocation directory: offset=\{offset}: \{message}")
      abort("relocation parse failed")
    }
  }
  if json_mode {
    println(relocations_json(blocks))
    return
  }
  for block in blocks {
    println("page=\{hex(block.page_rva)} entries=\{block.entries.length()}")
    for entry in block.entries {
      println(
        "  \{@pe.relocation_type_name(entry.relocation_type)} rva=\{hex(entry.target_rva)}",
      )
    }
  }
}

///|
fn delay_imports(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let libraries = image.delay_imports() catch {
    @pe.PeError(offset, message) => {
      println("invalid delay-import directory: offset=\{offset}: \{message}")
      abort("delay-import parse failed")
    }
  }
  if json_mode {
    println(delay_imports_json(libraries))
    return
  }
  for library in libraries {
    println(library.name)
    for symbol in library.symbols {
      match symbol.name {
        Some(name) => println("  \{name}")
        None => println("  #\{symbol.ordinal.unwrap()}")
      }
    }
  }
}

///|
fn tls(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let info = image.tls() catch {
    @pe.PeError(offset, message) => {
      println("invalid TLS directory: offset=\{offset}: \{message}")
      abort("TLS parse failed")
    }
  }
  if json_mode {
    println(tls_json(info))
    return
  }
  match info {
    Some(tls) => {
      println("raw-data: \{hex(tls.raw_data_start)}..\{hex(tls.raw_data_end)}")
      println("index-address: \{hex(tls.index_address)}")
      println("callbacks-address: \{hex(tls.callbacks_address)}")
      println("zero-fill: \{tls.size_of_zero_fill}")
      for callback in tls.callbacks {
        println("callback: \{hex(callback)}")
      }
    }
    None => println("no TLS directory")
  }
}

///|
fn debug(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let entries = image.debug_entries() catch {
    @pe.PeError(offset, message) => {
      println("invalid debug directory: offset=\{offset}: \{message}")
      abort("debug parse failed")
    }
  }
  if json_mode {
    println(debug_json(entries))
    return
  }
  for entry in entries {
    println(
      "\{entry.type_name}: size=\{entry.size_of_data} rva=\{hex(entry.address_of_raw_data)}",
    )
    match entry.pdb_path {
      Some(path) => println("  pdb=\{path} age=\{entry.pdb_age.unwrap()}")
      None => ()
    }
  }
}

///|
fn load_config(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let config = image.load_config() catch {
    @pe.PeError(offset, message) => {
      println("invalid load-config directory: offset=\{offset}: \{message}")
      abort("load-config parse failed")
    }
  }
  if json_mode {
    println(load_config_json(config))
    return
  }
  match config {
    Some(config) => {
      println("structure-size: \{config.structure_size}")
      println(
        "guard-flags: \{hex(config.guard_flags.unwrap_or(0).to_uint64())}",
      )
      println(
        "guard-function-count: \{config.guard_cf_function_count.unwrap_or(0)}",
      )
      println("security-cookie: \{hex(config.security_cookie.unwrap_or(0UL))}")
    }
    None => println("no load-config directory")
  }
}

///|
fn exceptions(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let entries = image.exception_entries() catch {
    @pe.PeError(offset, message) => {
      println("invalid exception directory: offset=\{offset}: \{message}")
      abort("exception parse failed")
    }
  }
  if json_mode {
    println(exceptions_json(entries))
    return
  }
  for entry in entries {
    println(
      "\{hex(entry.begin_rva)}..\{hex(entry.end_rva)} unwind=\{hex(entry.unwind_info_rva)}",
    )
  }
}

///|
fn bound_imports(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let imports = image.bound_imports() catch {
    @pe.PeError(offset, message) => {
      println("invalid bound-import directory: offset=\{offset}: \{message}")
      abort("bound-import parse failed")
    }
  }
  if json_mode {
    println(bound_imports_json(imports))
    return
  }
  for item in imports {
    println("\{item.name} timestamp=\{item.timestamp}")
    for forwarder in item.forwarders {
      println("  -> \{forwarder.name}")
    }
  }
}

///|
fn clr(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let header = image.clr_header() catch {
    @pe.PeError(offset, message) => {
      println("invalid CLR header: offset=\{offset}: \{message}")
      abort("CLR parse failed")
    }
  }
  if json_mode {
    println(clr_json(header))
    return
  }
  match header {
    Some(header) => {
      println(
        "runtime: \{header.major_runtime_version}.\{header.minor_runtime_version}",
      )
      println(
        "metadata: \{hex(header.metadata_rva)} size=\{header.metadata_size}",
      )
      println("flags: \{hex(header.flags.to_uint64())}")
      println("entry-token: \{hex(header.entry_point_token.to_uint64())}")
    }
    None => println("no CLR header")
  }
}

///|
fn certificates(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let records = image.certificates() catch {
    @pe.PeError(offset, message) => {
      println("invalid certificate table: offset=\{offset}: \{message}")
      abort("certificate parse failed")
    }
  }
  if json_mode {
    println(certificates_json(records))
    return
  }
  for record in records {
    println(
      "\{@pe.certificate_type_name(record.certificate_type)} revision=\{hex(record.revision.to_uint64())} length=\{record.length}",
    )
  }
}

///|
fn overlay(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let info = image.overlay()
  if json_mode {
    println(overlay_json(info))
    return
  }
  match info {
    Some(overlay) =>
      println(
        "overlay: offset=\{hex(overlay.offset.to_uint64())} size=\{overlay.size}",
      )
    None => println("no overlay")
  }
}

///|
fn checksum(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let checksum = image.checksum_info()
  if json_mode {
    println(checksum_json(checksum))
    return
  }
  println("stored: \{hex32(checksum.stored)}")
  println("computed: \{hex32(checksum.computed)}")
  println("present: \{checksum.present}")
  println("valid: \{checksum.valid}")
}

///|
fn rich(image : @pe.PEImage, json_mode : Bool) -> Unit {
  let rich = image.rich_header()
  if json_mode {
    println(rich_json(rich))
    return
  }
  match rich {
    Some(header) => {
      println("xor-key: \{hex(header.xor_key)}")
      for entry in header.entries {
        println(
          "product=\{entry.product_id} build=\{entry.build_id} count=\{entry.use_count}",
        )
      }
    }
    None => println("no Rich header")
  }
}

///|
fn lint(
  image : @pe.PEImage,
  path : String,
  json_mode : Bool,
  sarif_mode : Bool,
) -> Unit {
  let diagnostics = image.security_diagnostics()
  let passed = diagnostics_pass(diagnostics)
  if sarif_mode {
    println(security_sarif_json(diagnostics, path))
  } else if json_mode {
    println(lint_json(diagnostics, path, passed))
  } else {
    for diagnostic in diagnostics {
      println(
        "[\{severity_name(diagnostic.severity)}] \{diagnostic.code}: \{diagnostic.message}",
      )
    }
    println(if passed { "lint: PASS" } else { "lint: FAIL" })
  }
  if !passed {
    abort("security lint failed")
  }
}

///|
fn security_sarif(image : @pe.PEImage, path : String) -> Unit {
  println(security_sarif_json(image.security_diagnostics(), path))
}

///|
fn diagnostics_pass(diagnostics : Array[@pe.Diagnostic]) -> Bool {
  for diagnostic in diagnostics {
    if diagnostic.severity is @pe.Warning || diagnostic.severity is @pe.Critical {
      return false
    }
  }
  true
}

///|
async fn diff_files(
  left_path : String,
  right_path : String,
  json_mode : Bool,
) -> Unit {
  let left = load_image(left_path)
  let right = load_image(right_path)
  let changes = left.diff(right)
  if json_mode {
    println(diff_json(changes))
    return
  }
  if changes.is_empty() {
    println("no differences")
    return
  }
  for change in changes {
    println("\{change.field}: \{change.before} -> \{change.after}")
  }
}

///|
fn inspect_json(image : @pe.PEImage) -> String {
  let builder = StringBuilder()
  builder.write_string("{\"format\":")
  write_json_string(builder, format_name(image.format))
  builder.write_string(",\"machine\":")
  write_json_string(builder, @pe.architecture_name(image.machine))
  builder.write_string(",\"subsystem\":")
  write_json_string(builder, @pe.subsystem_name(image.subsystem))
  builder.write_string(",\"imageBase\":")
  write_json_string(builder, hex(image.image_base))
  builder.write_string(",\"entryPoint\":")
  write_json_string(builder, hex(image.entry_point))
  builder.write_string(",\"sizeOfImage\":")
  builder.write_string(image.size_of_image.to_string())
  builder.write_string(",\"sections\":")
  builder.write_string(image.number_of_sections.to_string())
  builder.write_string(",\"directories\":")
  builder.write_string(directories_json(image))
  builder.write_string(",\"overlay\":")
  builder.write_string(overlay_json(image.overlay()))
  builder.write_string(",\"diagnostics\":")
  write_diagnostics(builder, image.security_diagnostics())
  builder.write_string("}")
  builder.to_string()
}

///|
fn sections_json(image : @pe.PEImage) -> String {
  let entropies = image.section_entropies() catch { @pe.PeError(_, _) => [] }
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for index in 0..<image.sections.length() {
    let section = image.sections[index]
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"name\":")
    write_json_string(builder, section.name)
    builder.write_string(",\"virtualAddress\":")
    write_json_string(builder, hex(section.virtual_address))
    builder.write_string(",\"virtualSize\":")
    builder.write_string(section.virtual_size.to_string())
    builder.write_string(",\"rawOffset\":")
    write_json_string(builder, hex(section.raw_offset.to_uint64()))
    builder.write_string(",\"rawSize\":")
    builder.write_string(section.raw_size.to_string())
    if entropies.length() == image.sections.length() {
      builder.write_string(",\"entropy\":")
      builder.write_string(entropies[index].entropy.to_string())
    }
    builder.write_string(",\"characteristics\":")
    write_json_string(builder, hex(section.characteristics))
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn imports_json(libraries : Array[@pe.ImportLibrary]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for library in libraries {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"library\":")
    write_json_string(builder, library.name)
    builder.write_string(",\"symbols\":[")
    let mut first_symbol = true
    for symbol in library.symbols {
      if !first_symbol {
        builder.write_char(',')
      }
      first_symbol = false
      builder.write_string("{\"name\":")
      match symbol.name {
        Some(name) => write_json_string(builder, name)
        None => builder.write_string("null")
      }
      builder.write_string(",\"ordinal\":")
      match symbol.ordinal {
        Some(ordinal) => builder.write_string(ordinal.to_string())
        None => builder.write_string("null")
      }
      builder.write_string(",\"hint\":")
      match symbol.hint {
        Some(hint) => builder.write_string(hint.to_string())
        None => builder.write_string("null")
      }
      builder.write_char('}')
    }
    builder.write_string("]}")
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn exports_json(symbols : Array[@pe.ExportSymbol]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for symbol in symbols {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"name\":")
    write_json_string(builder, symbol.name)
    builder.write_string(",\"ordinal\":")
    builder.write_string(symbol.ordinal.to_string())
    builder.write_string(",\"rva\":")
    write_json_string(builder, hex(symbol.rva))
    builder.write_string(",\"forwarder\":")
    match symbol.forwarder {
      Some(target) => write_json_string(builder, target)
      None => builder.write_string("null")
    }
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn directories_json(image : @pe.PEImage) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for directory in image.directories {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"index\":")
    builder.write_string(directory.index.to_string())
    builder.write_string(",\"name\":")
    write_json_string(builder, directory.name)
    builder.write_string(",\"rva\":")
    write_json_string(builder, hex(directory.virtual_address))
    builder.write_string(",\"size\":")
    builder.write_string(directory.size.to_string())
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn resources_json(entries : Array[@pe.ResourceEntry]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for entry in entries {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"path\":")
    write_json_string(builder, entry.path)
    builder.write_string(",\"dataRva\":")
    write_json_string(builder, hex(entry.data_rva))
    builder.write_string(",\"size\":")
    builder.write_string(entry.size.to_string())
    builder.write_string(",\"codePage\":")
    builder.write_string(entry.code_page.to_string())
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn relocations_json(blocks : Array[@pe.RelocationBlock]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for block in blocks {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"pageRva\":")
    write_json_string(builder, hex(block.page_rva))
    builder.write_string(",\"entries\":[")
    let mut first_entry = true
    for entry in block.entries {
      if !first_entry {
        builder.write_char(',')
      }
      first_entry = false
      builder.write_string("{\"type\":")
      write_json_string(
        builder,
        @pe.relocation_type_name(entry.relocation_type),
      )
      builder.write_string(",\"targetRva\":")
      write_json_string(builder, hex(entry.target_rva))
      builder.write_char('}')
    }
    builder.write_string("]}")
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn delay_imports_json(libraries : Array[@pe.DelayImportLibrary]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for library in libraries {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"library\":")
    write_json_string(builder, library.name)
    builder.write_string(",\"attributes\":")
    builder.write_string(library.attributes.to_string())
    builder.write_string(",\"symbols\":[")
    let mut first_symbol = true
    for symbol in library.symbols {
      if !first_symbol {
        builder.write_char(',')
      }
      first_symbol = false
      builder.write_string("{\"name\":")
      match symbol.name {
        Some(name) => write_json_string(builder, name)
        None => builder.write_string("null")
      }
      builder.write_string(",\"ordinal\":")
      match symbol.ordinal {
        Some(ordinal) => builder.write_string(ordinal.to_string())
        None => builder.write_string("null")
      }
      builder.write_char('}')
    }
    builder.write_string("]}")
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn tls_json(info : @pe.TlsInfo?) -> String {
  match info {
    None => "null"
    Some(tls) => {
      let builder = StringBuilder()
      builder.write_string("{\"rawDataStart\":")
      write_json_string(builder, hex(tls.raw_data_start))
      builder.write_string(",\"rawDataEnd\":")
      write_json_string(builder, hex(tls.raw_data_end))
      builder.write_string(",\"indexAddress\":")
      write_json_string(builder, hex(tls.index_address))
      builder.write_string(",\"callbacksAddress\":")
      write_json_string(builder, hex(tls.callbacks_address))
      builder.write_string(",\"sizeOfZeroFill\":")
      builder.write_string(tls.size_of_zero_fill.to_string())
      builder.write_string(",\"callbacks\":[")
      let mut first = true
      for callback in tls.callbacks {
        if !first {
          builder.write_char(',')
        }
        first = false
        write_json_string(builder, hex(callback))
      }
      builder.write_string("]}")
      builder.to_string()
    }
  }
}

///|
fn debug_json(entries : Array[@pe.DebugEntry]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for entry in entries {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"type\":")
    write_json_string(builder, entry.type_name)
    builder.write_string(",\"size\":")
    builder.write_string(entry.size_of_data.to_string())
    builder.write_string(",\"rva\":")
    write_json_string(builder, hex(entry.address_of_raw_data))
    builder.write_string(",\"pdb\":")
    match entry.pdb_path {
      Some(path) => write_json_string(builder, path)
      None => builder.write_string("null")
    }
    builder.write_string(",\"age\":")
    match entry.pdb_age {
      Some(age) => builder.write_string(age.to_string())
      None => builder.write_string("null")
    }
    builder.write_string(",\"guid\":")
    match entry.pdb_guid {
      Some(guid) => write_json_string(builder, guid)
      None => builder.write_string("null")
    }
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn load_config_json(config : @pe.LoadConfigInfo?) -> String {
  match config {
    None => "null"
    Some(config) => {
      let builder = StringBuilder()
      builder.write_string("{\"structureSize\":")
      builder.write_string(config.structure_size.to_string())
      builder.write_string(",\"guardFlags\":")
      match config.guard_flags {
        Some(value) => builder.write_string(value.to_string())
        None => builder.write_string("null")
      }
      builder.write_string(",\"guardFunctionCount\":")
      match config.guard_cf_function_count {
        Some(value) => builder.write_string(value.to_string())
        None => builder.write_string("null")
      }
      builder.write_string(",\"securityCookie\":")
      match config.security_cookie {
        Some(value) => write_json_string(builder, hex(value))
        None => builder.write_string("null")
      }
      builder.write_char('}')
      builder.to_string()
    }
  }
}

///|
fn exceptions_json(entries : Array[@pe.ExceptionEntry]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for entry in entries {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"beginRva\":")
    write_json_string(builder, hex(entry.begin_rva))
    builder.write_string(",\"endRva\":")
    write_json_string(builder, hex(entry.end_rva))
    builder.write_string(",\"unwindInfoRva\":")
    write_json_string(builder, hex(entry.unwind_info_rva))
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn bound_imports_json(imports : Array[@pe.BoundImport]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for item in imports {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"name\":")
    write_json_string(builder, item.name)
    builder.write_string(",\"timestamp\":")
    builder.write_string(item.timestamp.to_string())
    builder.write_string(",\"forwarders\":[")
    let mut first_forwarder = true
    for forwarder in item.forwarders {
      if !first_forwarder {
        builder.write_char(',')
      }
      first_forwarder = false
      builder.write_string("{\"name\":")
      write_json_string(builder, forwarder.name)
      builder.write_string(",\"timestamp\":")
      builder.write_string(forwarder.timestamp.to_string())
      builder.write_char('}')
    }
    builder.write_string("]}")
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn clr_json(header : @pe.ClrHeaderInfo?) -> String {
  match header {
    None => "null"
    Some(header) => {
      let builder = StringBuilder()
      builder.write_string("{\"runtime\":")
      write_json_string(
        builder,
        "\{header.major_runtime_version}.\{header.minor_runtime_version}",
      )
      builder.write_string(",\"metadataRva\":")
      write_json_string(builder, hex(header.metadata_rva))
      builder.write_string(",\"metadataSize\":")
      builder.write_string(header.metadata_size.to_string())
      builder.write_string(",\"flags\":")
      builder.write_string(header.flags.to_string())
      builder.write_string(",\"entryPointToken\":")
      builder.write_string(header.entry_point_token.to_string())
      builder.write_char('}')
      builder.to_string()
    }
  }
}

///|
fn certificates_json(records : Array[@pe.CertificateRecord]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for record in records {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"type\":")
    write_json_string(
      builder,
      @pe.certificate_type_name(record.certificate_type),
    )
    builder.write_string(",\"revision\":")
    builder.write_string(record.revision.to_string())
    builder.write_string(",\"length\":")
    builder.write_string(record.length.to_string())
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn overlay_json(info : @pe.OverlayInfo?) -> String {
  match info {
    None => "null"
    Some(overlay) => {
      let builder = StringBuilder()
      builder.write_string("{\"offset\":")
      write_json_string(builder, hex(overlay.offset.to_uint64()))
      builder.write_string(",\"size\":")
      builder.write_string(overlay.size.to_string())
      builder.write_char('}')
      builder.to_string()
    }
  }
}

///|
fn checksum_json(checksum : @pe.ChecksumInfo) -> String {
  let builder = StringBuilder()
  builder.write_string("{\"stored\":")
  write_json_string(builder, hex32(checksum.stored))
  builder.write_string(",\"computed\":")
  write_json_string(builder, hex32(checksum.computed))
  builder.write_string(",\"present\":")
  builder.write_string(if checksum.present { "true" } else { "false" })
  builder.write_string(",\"valid\":")
  builder.write_string(if checksum.valid { "true" } else { "false" })
  builder.write_char('}')
  builder.to_string()
}

///|
fn rich_json(rich : @pe.RichHeaderInfo?) -> String {
  match rich {
    None => "null"
    Some(header) => {
      let builder = StringBuilder()
      builder.write_string("{\"xorKey\":")
      write_json_string(builder, hex(header.xor_key))
      builder.write_string(",\"entries\":[")
      let mut first = true
      for entry in header.entries {
        if !first {
          builder.write_char(',')
        }
        first = false
        builder.write_string("{\"productId\":")
        builder.write_string(entry.product_id.to_string())
        builder.write_string(",\"buildId\":")
        builder.write_string(entry.build_id.to_string())
        builder.write_string(",\"count\":")
        builder.write_string(entry.use_count.to_string())
        builder.write_char('}')
      }
      builder.write_string("]}")
      builder.to_string()
    }
  }
}

///|
fn lint_json(
  diagnostics : Array[@pe.Diagnostic],
  path : String,
  passed : Bool,
) -> String {
  let builder = StringBuilder()
  builder.write_string("{\"path\":")
  write_json_string(builder, path)
  builder.write_string(",\"passed\":")
  builder.write_string(if passed { "true" } else { "false" })
  builder.write_string(",\"diagnostics\":")
  builder.write_string(diagnostics_json(diagnostics))
  builder.write_char('}')
  builder.to_string()
}

///|
fn security_sarif_json(
  diagnostics : Array[@pe.Diagnostic],
  path : String,
) -> String {
  let rules = []
  for diagnostic in diagnostics {
    if !rules.contains(diagnostic.code) {
      rules.push(diagnostic.code)
    }
  }
  let builder = StringBuilder()
  builder.write_string(
    "{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\"",
  )
  builder.write_string(
    ",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{",
  )
  builder.write_string("\"name\":\"moon-pe-inspect\",\"version\":")
  write_json_string(builder, VERSION)
  builder.write_string(",\"informationUri\":")
  write_json_string(builder, "https://github.com/404-32/byc001")
  builder.write_string(",\"rules\":[")
  let mut first_rule = true
  for rule in rules {
    if !first_rule {
      builder.write_char(',')
    }
    first_rule = false
    builder.write_string("{\"id\":")
    write_json_string(builder, rule)
    builder.write_string(",\"shortDescription\":{\"text\":")
    write_json_string(builder, "PE security rule \{rule}")
    builder.write_string("}}")
  }
  builder.write_string("]}},\"results\":[")
  let mut first_result = true
  for diagnostic in diagnostics {
    if !first_result {
      builder.write_char(',')
    }
    first_result = false
    builder.write_string("{\"ruleId\":")
    write_json_string(builder, diagnostic.code)
    builder.write_string(",\"level\":")
    write_json_string(builder, sarif_level(diagnostic.severity))
    builder.write_string(",\"message\":{\"text\":")
    write_json_string(builder, diagnostic.message)
    builder.write_string(
      "},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":",
    )
    write_json_string(builder, slash_path(path))
    builder.write_string("}}}]}")
  }
  builder.write_string("]}]}")
  builder.to_string()
}

///|
fn sarif_level(severity : @pe.Severity) -> String {
  match severity {
    @pe.Critical => "error"
    @pe.Warning => "warning"
    @pe.Info => "note"
  }
}

///|
fn slash_path(path : String) -> String {
  let builder = StringBuilder()
  for char in path {
    builder.write_char(if char == '\\' { '/' } else { char })
  }
  builder.to_string()
}

///|
fn diff_json(changes : Array[@pe.DiffItem]) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for change in changes {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"field\":")
    write_json_string(builder, change.field)
    builder.write_string(",\"before\":")
    write_json_string(builder, change.before)
    builder.write_string(",\"after\":")
    write_json_string(builder, change.after)
    builder.write_char('}')
  }
  builder.write_char(']')
  builder.to_string()
}

///|
fn diagnostics_json(diagnostics : Array[@pe.Diagnostic]) -> String {
  let builder = StringBuilder()
  write_diagnostics(builder, diagnostics)
  builder.to_string()
}

///|
fn write_diagnostics(
  builder : StringBuilder,
  diagnostics : Array[@pe.Diagnostic],
) -> Unit {
  builder.write_char('[')
  let mut first = true
  for diagnostic in diagnostics {
    if !first {
      builder.write_char(',')
    }
    first = false
    builder.write_string("{\"severity\":")
    write_json_string(builder, severity_name(diagnostic.severity))
    builder.write_string(",\"code\":")
    write_json_string(builder, diagnostic.code)
    builder.write_string(",\"message\":")
    write_json_string(builder, diagnostic.message)
    builder.write_char('}')
  }
  builder.write_char(']')
}

///|
fn format_name(format : @pe.PEFormat) -> String {
  if format is @pe.PE32 {
    "PE32"
  } else {
    "PE32+"
  }
}

///|
fn severity_name(severity : @pe.Severity) -> String {
  match severity {
    @pe.Info => "info"
    @pe.Warning => "warning"
    @pe.Critical => "critical"
  }
}

///|
fn hex(value : UInt64) -> String {
  if value == 0UL {
    return "0x0"
  }
  let reversed = []
  let mut current = value
  while current != 0UL {
    reversed.push(hex_digit(current.land(0xfUL).to_int()))
    current = current >> 4
  }
  let result = StringBuilder()
  result.write_string("0x")
  let mut index = reversed.length() - 1
  while index >= 0 {
    result.write_char(reversed[index])
    index = index - 1
  }
  result.to_string()
}

///|
fn hex32(value : Int32) -> String {
  hex(value.to_uint64().land(0xffffffffUL))
}

///|
fn hex_digit(value : Int32) -> Char {
  if value < 10 {
    ('0'.to_int() + value).unsafe_to_char()
  } else {
    ('a'.to_int() + value - 10).unsafe_to_char()
  }
}

///|
fn write_json_string(builder : StringBuilder, value : String) -> Unit {
  builder.write_char('"')
  for char in value {
    match char {
      '"' => builder.write_string("\\\"")
      '\\' => builder.write_string("\\\\")
      '\n' => builder.write_string("\\n")
      '\r' => builder.write_string("\\r")
      '\t' => builder.write_string("\\t")
      _ => builder.write_char(char)
    }
  }
  builder.write_char('"')
}
