// SPDX-License-Identifier: Apache-2.0

///|
pub(all) struct CoffSection {
  name : String
  virtual_size : Int32
  virtual_address : UInt64
  raw_size : Int32
  raw_offset : Int32
  relocation_offset : Int32
  line_number_offset : Int32
  relocation_count : Int32
  line_number_count : Int32
  characteristics : UInt64
}

///|
pub(all) struct CoffSymbol {
  name : String
  value : UInt64
  section_number : Int32
  symbol_type : Int32
  storage_class : Int32
}

///|
pub(all) struct CoffObject {
  machine : Int32
  section_count : Int32
  timestamp : Int32
  symbol_table_pointer : Int32
  symbol_count : Int32
  optional_header_size : Int32
  characteristics : Int32
  sections : Array[CoffSection]
  symbols : Array[CoffSymbol]
}

///|
pub fn CoffObject::parse(data : Bytes) -> Self raise PeError {
  if data.length() < 20 {
    raise PeError(0, "file is too small to contain a COFF header")
  }
  let machine = read_u16(data, 0)
  let section_count = read_u16(data, 2)
  if section_count > 4096 {
    raise PeError(2, "COFF section count exceeds the safety limit")
  }
  let timestamp = checked_int(read_u32(data, 4), 4, "COFF timestamp")
  let symbol_table_pointer = checked_int(
    read_u32(data, 8),
    8,
    "COFF symbol-table pointer",
  )
  let symbol_count = checked_int(read_u32(data, 12), 12, "COFF symbol count")
  let optional_header_size = read_u16(data, 16)
  let characteristics = read_u16(data, 18)
  let sections_offset = 20 + optional_header_size
  ensure_range(data, sections_offset, section_count * 40)
  let string_table_offset = if symbol_table_pointer > 0 && symbol_count > 0 {
    Some(symbol_table_pointer + symbol_count * 18)
  } else {
    None
  }
  let sections = []
  for index in 0..<section_count {
    let offset = sections_offset + index * 40
    let short_name = read_ascii_fixed(data, offset, 8)
    let name_offset = decimal_tail(short_name)
    let name = if name_offset >= 0 {
      match string_table_offset {
        Some(table_offset) => read_coff_string(data, table_offset, name_offset)
        None => short_name
      }
    } else {
      short_name
    }
    let virtual_size = checked_int(
      read_u32(data, offset + 8),
      offset + 8,
      "COFF section virtual size",
    )
    let virtual_address = read_u32(data, offset + 12)
    let raw_size = checked_int(
      read_u32(data, offset + 16),
      offset + 16,
      "COFF section raw size",
    )
    let raw_offset = checked_int(
      read_u32(data, offset + 20),
      offset + 20,
      "COFF section raw offset",
    )
    let relocation_offset = checked_int(
      read_u32(data, offset + 24),
      offset + 24,
      "COFF relocation offset",
    )
    let line_number_offset = checked_int(
      read_u32(data, offset + 28),
      offset + 28,
      "COFF line-number offset",
    )
    if raw_size > 0 {
      ensure_range(data, raw_offset, raw_size)
    }
    sections.push({
      name,
      virtual_size,
      virtual_address,
      raw_size,
      raw_offset,
      relocation_offset,
      line_number_offset,
      relocation_count: read_u16(data, offset + 32),
      line_number_count: read_u16(data, offset + 34),
      characteristics: read_u32(data, offset + 36),
    })
  }
  let symbols = if symbol_table_pointer > 0 && symbol_count > 0 {
    read_coff_symbols(
      data, symbol_table_pointer, symbol_count, string_table_offset,
    )
  } else {
    []
  }
  {
    machine,
    section_count,
    timestamp,
    symbol_table_pointer,
    symbol_count,
    optional_header_size,
    characteristics,
    sections,
    symbols,
  }
}

///|
fn decimal_tail(text : String) -> Int32 {
  if !text.has_prefix("/") || text.length() < 2 {
    return -1
  }
  let chars = text.to_array()
  let mut value = 0
  let mut index = 1
  while index < chars.length() {
    let char = chars[index]
    if char < '0' || char > '9' {
      return -1
    }
    value = value * 10 + (char.to_int() - '0'.to_int())
    index = index + 1
  }
  value
}

///|
fn read_coff_symbols(
  data : Bytes,
  table_offset : Int32,
  symbol_count : Int32,
  string_table_offset : Int32?,
) -> Array[CoffSymbol] raise PeError {
  ensure_range(data, table_offset, symbol_count * 18)
  let symbols = []
  let limit = if symbol_count < 65536 { symbol_count } else { 65536 }
  let mut index = 0
  while index < limit {
    let offset = table_offset + index * 18
    let raw_name = read_u32(data, offset)
    let name = if raw_name == 0UL {
      let string_offset = checked_int(
        read_u32(data, offset + 4),
        offset + 4,
        "COFF symbol string offset",
      )
      match string_table_offset {
        Some(table_offset) =>
          read_coff_string(data, table_offset, string_offset)
        None => "<missing-string-table>"
      }
    } else {
      read_ascii_fixed(data, offset, 8)
    }
    let raw_section = read_u16(data, offset + 12)
    let section_number = if raw_section >= 0x8000 {
      raw_section - 0x10000
    } else {
      raw_section
    }
    symbols.push({
      name,
      value: read_u32(data, offset + 8),
      section_number,
      symbol_type: read_u16(data, offset + 14),
      storage_class: read_u8(data, offset + 16),
    })
    let aux_count = read_u8(data, offset + 17)
    index = index + 1 + aux_count
  }
  symbols
}

///|
fn read_coff_string(
  data : Bytes,
  table_offset : Int32,
  string_offset : Int32,
) -> String raise PeError {
  ensure_range(data, table_offset, 4)
  let table_size = checked_int(
    read_u32(data, table_offset),
    table_offset,
    "COFF string-table size",
  )
  if table_size < 4 {
    raise PeError(table_offset, "invalid COFF string-table size")
  }
  ensure_range(data, table_offset, table_size)
  if string_offset < 4 || string_offset >= table_size {
    raise PeError(table_offset + string_offset, "invalid COFF string offset")
  }
  read_ascii_z(data, table_offset + string_offset, table_size - string_offset)
}
