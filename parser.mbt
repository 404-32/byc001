///|
pub fn PEImage::parse(data : Bytes) -> Self raise PeError {
  if data.length() < 64 {
    raise PeError(0, "file is too small to contain a DOS header")
  }
  if read_u8(data, 0) != 0x4d || read_u8(data, 1) != 0x5a {
    raise PeError(0, "missing MZ DOS signature")
  }
  let pe_offset = checked_int(read_u32(data, 0x3c), 0x3c, "e_lfanew")
  ensure_range(data, pe_offset, 24)
  if read_u8(data, pe_offset) != 0x50 ||
    read_u8(data, pe_offset + 1) != 0x45 ||
    read_u8(data, pe_offset + 2) != 0 ||
    read_u8(data, pe_offset + 3) != 0 {
    raise PeError(pe_offset, "missing PE signature")
  }
  let coff = pe_offset + 4
  let machine = read_u16(data, coff)
  let number_of_sections = read_u16(data, coff + 2)
  if number_of_sections > 1024 {
    raise PeError(coff + 2, "section count exceeds the safety limit")
  }
  let timestamp = read_u32(data, coff + 4)
  let symbol_table_pointer = read_u32(data, coff + 8)
  let number_of_symbols = read_u32(data, coff + 12)
  let size_of_optional_header = read_u16(data, coff + 16)
  let characteristics = read_u16(data, coff + 18)
  let optional = coff + 20
  ensure_range(data, optional, size_of_optional_header)
  if size_of_optional_header < 2 {
    raise PeError(optional, "optional header is missing")
  }
  let magic = read_u16(data, optional)
  let format = if magic == 0x10b {
    PE32
  } else if magic == 0x20b {
    PE32Plus
  } else {
    raise PeError(optional, "unsupported optional-header magic")
  }
  let minimum_optional = if format is PE32 { 96 } else { 112 }
  if size_of_optional_header < minimum_optional {
    raise PeError(optional, "optional header is truncated")
  }
  let entry_point = read_u32(data, optional + 16)
  let image_base = if format is PE32 {
    read_u32(data, optional + 28)
  } else {
    read_u64(data, optional + 24)
  }
  let section_alignment = checked_int(
    read_u32(data, optional + 32),
    optional + 32,
    "section alignment",
  )
  let file_alignment = checked_int(
    read_u32(data, optional + 36),
    optional + 36,
    "file alignment",
  )
  let size_of_image = checked_int(
    read_u32(data, optional + 56),
    optional + 56,
    "image size",
  )
  let size_of_headers = checked_int(
    read_u32(data, optional + 60),
    optional + 60,
    "header size",
  )
  let checksum = read_u32(data, optional + 64)
  let subsystem = read_u16(data, optional + 68)
  let dll_characteristics = read_u16(data, optional + 70)
  let number_of_directories = if format is PE32 {
    read_u32(data, optional + 92)
  } else {
    read_u32(data, optional + 108)
  }
  let directories_offset = if format is PE32 {
    optional + 96
  } else {
    optional + 112
  }
  let optional_end = optional + size_of_optional_header
  let available_directories = if directories_offset <= optional_end {
    (optional_end - directories_offset) / 8
  } else {
    0
  }
  let directory_limit = if number_of_directories < 16UL {
    number_of_directories.to_int()
  } else {
    16
  }
  let directory_count = if directory_limit < available_directories {
    directory_limit
  } else {
    available_directories
  }
  let directories = []
  for index in 0..<directory_count {
    let offset = directories_offset + index * 8
    let virtual_address = read_u32(data, offset)
    let size = checked_int(
      read_u32(data, offset + 4),
      offset + 4,
      "directory size",
    )
    directories.push({
      index,
      name: directory_name(index),
      virtual_address,
      size,
    })
  }
  let sections_offset = optional_end
  let section_bytes = number_of_sections * 40
  ensure_range(data, sections_offset, section_bytes)
  let sections = []
  for index in 0..<number_of_sections {
    let offset = sections_offset + index * 40
    let name = read_ascii_fixed(data, offset, 8)
    let virtual_size = checked_int(
      read_u32(data, offset + 8),
      offset + 8,
      "section virtual size",
    )
    let virtual_address = read_u32(data, offset + 12)
    let raw_size = checked_int(
      read_u32(data, offset + 16),
      offset + 16,
      "section raw size",
    )
    let raw_offset = checked_int(
      read_u32(data, offset + 20),
      offset + 20,
      "section file offset",
    )
    let section_characteristics = read_u32(data, offset + 36)
    if raw_size > 0 {
      ensure_range(data, raw_offset, raw_size)
    }
    sections.push({
      name,
      virtual_size,
      virtual_address,
      raw_size,
      raw_offset,
      characteristics: section_characteristics,
    })
  }
  {
    data,
    pe_offset,
    format,
    machine,
    number_of_sections,
    timestamp,
    symbol_table_pointer,
    number_of_symbols,
    size_of_optional_header,
    characteristics,
    entry_point,
    image_base,
    section_alignment,
    file_alignment,
    size_of_image,
    size_of_headers,
    checksum,
    subsystem,
    dll_characteristics,
    sections,
    directories,
  }
}

///|
pub fn PEImage::rva_to_offset(self : Self, rva : UInt64) -> Int32 raise PeError {
  if rva < self.size_of_headers.to_uint64() {
    return checked_int(rva, 0, "RVA")
  }
  for section in self.sections {
    let span = if section.virtual_size > section.raw_size {
      section.virtual_size
    } else {
      section.raw_size
    }
    let start = section.virtual_address
    let end = start + span.to_uint64()
    if rva >= start && rva < end {
      let delta = rva - start
      if delta >= section.raw_size.to_uint64() {
        raise PeError(
          section.raw_offset,
          "RVA points to uninitialized section data",
        )
      }
      return section.raw_offset + checked_int(delta, 0, "RVA delta")
    }
  }
  raise PeError(0, "RVA is not mapped by any section")
}

///|
pub fn PEImage::read_c_string(
  self : Self,
  rva : UInt64,
  max_length : Int32,
) -> String raise PeError {
  let offset = self.rva_to_offset(rva)
  read_ascii_z(self.data, offset, max_length)
}

///|
fn directory_name(index : Int32) -> String {
  match index {
    0 => "export"
    1 => "import"
    2 => "resource"
    3 => "exception"
    4 => "certificate"
    5 => "base-reloc"
    6 => "debug"
    7 => "architecture"
    8 => "global-pointer"
    9 => "tls"
    10 => "load-config"
    11 => "bound-import"
    12 => "iat"
    13 => "delay-import"
    14 => "clr-runtime"
    _ => "reserved"
  }
}
