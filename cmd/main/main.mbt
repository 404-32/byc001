///|
const VERSION : String = "0.1.0"

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
  for arg_index in 1..<args.length() {
    if args[arg_index] == "--json" {
      json_mode = true
    } else {
      positionals.push(args[arg_index])
    }
  }
  if positionals.length() != 1 {
    println(USAGE)
    abort("expected exactly one PE file")
  }
  let image = load_image(positionals[0])
  match command {
    "inspect" => inspect(image, json_mode)
    "sections" => sections(image, json_mode)
    "imports" => imports(image, json_mode)
    "exports" => exports(image, json_mode)
    "security" => security(image, json_mode)
    _ => {
      println("unknown command: \{command}")
      println(USAGE)
      abort("unknown command")
    }
  }
}

///|
async fn load_image(path : String) -> @pe.PEImage {
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
  @pe.PEImage::parse(bytes) catch {
    @pe.PeError(offset, message) => {
      println("invalid PE file: offset=\{offset}: \{message}")
      abort("PE parse failed")
    }
  }
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
  for section in image.sections {
    println(
      "\{section.name}: va=\{hex(section.virtual_address)} vsize=\{section.virtual_size} raw=\{hex(section.raw_offset.to_uint64())}/\{section.raw_size} flags=\{hex(section.characteristics)}",
    )
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
  builder.write_string(",\"diagnostics\":")
  write_diagnostics(builder, image.security_diagnostics())
  builder.write_string("}")
  builder.to_string()
}

///|
fn sections_json(image : @pe.PEImage) -> String {
  let builder = StringBuilder()
  builder.write_char('[')
  let mut first = true
  for section in image.sections {
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
