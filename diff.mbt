// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::diff(self : Self, other : Self) -> Array[DiffItem] {
  let changes = []
  compare_field(
    changes,
    "format",
    format_text(self.format),
    format_text(other.format),
  )
  compare_field(
    changes,
    "machine",
    architecture_name(self.machine),
    architecture_name(other.machine),
  )
  compare_field(
    changes,
    "subsystem",
    subsystem_name(self.subsystem),
    subsystem_name(other.subsystem),
  )
  compare_field(
    changes,
    "image-base",
    self.image_base.to_string(),
    other.image_base.to_string(),
  )
  compare_field(
    changes,
    "entry-point",
    self.entry_point.to_string(),
    other.entry_point.to_string(),
  )
  compare_field(
    changes,
    "image-size",
    self.size_of_image.to_string(),
    other.size_of_image.to_string(),
  )
  compare_field(
    changes,
    "dll-characteristics",
    self.dll_characteristics.to_string(),
    other.dll_characteristics.to_string(),
  )
  compare_field(
    changes,
    "sections",
    sections_signature(self),
    sections_signature(other),
  )
  compare_field(
    changes,
    "imports",
    imports_signature(self),
    imports_signature(other),
  )
  compare_field(
    changes,
    "exports",
    exports_signature(self),
    exports_signature(other),
  )
  compare_field(
    changes,
    "directories",
    directories_signature(self),
    directories_signature(other),
  )
  compare_field(
    changes,
    "bound-imports",
    bound_imports_signature(self),
    bound_imports_signature(other),
  )
  compare_field(changes, "clr", clr_signature(self), clr_signature(other))
  compare_field(
    changes,
    "certificates",
    certificates_signature(self),
    certificates_signature(other),
  )
  compare_field(
    changes,
    "overlay",
    overlay_signature(self),
    overlay_signature(other),
  )
  compare_field(
    changes,
    "checksum",
    checksum_signature(self),
    checksum_signature(other),
  )
  compare_field(
    changes,
    "security-diagnostics",
    diagnostics_signature(self),
    diagnostics_signature(other),
  )
  changes
}

///|
fn compare_field(
  changes : Array[DiffItem],
  field : String,
  before : String,
  after : String,
) -> Unit {
  if before != after {
    changes.push({ field, before, after, })
  }
}

///|
fn sections_signature(image : PEImage) -> String {
  let values = []
  for section in image.sections {
    values.push(
      "\{section.name}:\{section.virtual_size}/\{section.raw_size}/\{section.characteristics}",
    )
  }
  values.join(",")
}

///|
fn imports_signature(image : PEImage) -> String {
  try {
    let values = []
    for library in image.imports() {
      values.push("\{library.name}(\{library.symbols.length()})")
    }
    values.join(",")
  } catch {
    PeError(_, _) => "<unreadable>"
  }
}

///|
fn exports_signature(image : PEImage) -> String {
  try {
    let values = []
    for symbol in image.exports() {
      values.push(symbol.name)
    }
    values.join(",")
  } catch {
    PeError(_, _) => "<unreadable>"
  }
}

///|
fn directories_signature(image : PEImage) -> String {
  let values = []
  for directory in image.directories {
    if directory.virtual_address != 0UL && directory.size > 0 {
      values.push(directory.name)
    }
  }
  values.join(",")
}

///|
fn bound_imports_signature(image : PEImage) -> String {
  try {
    let values = []
    for item in image.bound_imports() {
      values.push("\{item.name}(\{item.forwarders.length()})")
    }
    values.join(",")
  } catch {
    PeError(_, _) => "<unreadable>"
  }
}

///|
fn clr_signature(image : PEImage) -> String {
  try {
    match image.clr_header() {
      Some(header) =>
        "\{header.metadata_rva}/\{header.metadata_size}/\{header.entry_point_token}"
      None => ""
    }
  } catch {
    PeError(_, _) => "<unreadable>"
  }
}

///|
fn certificates_signature(image : PEImage) -> String {
  try {
    let values = []
    for record in image.certificates() {
      values.push("\{record.certificate_type}:\{record.length}")
    }
    values.join(",")
  } catch {
    PeError(_, _) => "<unreadable>"
  }
}

///|
fn overlay_signature(image : PEImage) -> String {
  match image.overlay() {
    Some(overlay) => "\{overlay.offset}:\{overlay.size}"
    None => ""
  }
}

///|
fn checksum_signature(image : PEImage) -> String {
  let checksum = image.checksum_info()
  "\{checksum.present}/\{checksum.valid}/\{checksum.computed}"
}

///|
fn diagnostics_signature(image : PEImage) -> String {
  let values = []
  for diagnostic in image.security_diagnostics() {
    values.push(diagnostic.code)
  }
  values.join(",")
}

///|
fn format_text(format : PEFormat) -> String {
  if format is PE32 {
    "PE32"
  } else {
    "PE32+"
  }
}
