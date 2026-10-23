///|
pub fn PEImage::debug_entries(self : Self) -> Array[DebugEntry] raise PeError {
  let directory = match self.directory(6) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let start = self.rva_to_offset(directory.virtual_address)
  let count = if directory.size / 28 < 4096 {
    directory.size / 28
  } else {
    4096
  }
  let entries = []
  for index in 0..<count {
    let offset = start + index * 28
    ensure_range(self.data, offset, 28)
    let debug_type = checked_int(
      read_u32(self.data, offset + 12),
      offset + 12,
      "debug type",
    )
    let size_of_data = checked_int(
      read_u32(self.data, offset + 16),
      offset + 16,
      "debug data size",
    )
    let address_of_raw_data = read_u32(self.data, offset + 20)
    let pointer_to_raw_data = checked_int(
      read_u32(self.data, offset + 24),
      offset + 24,
      "debug raw pointer",
    )
    let (pdb_path, pdb_age, pdb_guid) = if debug_type == 2 &&
      address_of_raw_data != 0UL &&
      size_of_data >= 4 {
      self.read_codeview(address_of_raw_data, size_of_data)
    } else {
      (None, None, None)
    }
    entries.push({
      debug_type,
      type_name: debug_type_name(debug_type),
      timestamp: checked_int(
        read_u32(self.data, offset + 4),
        offset + 4,
        "debug timestamp",
      ),
      size_of_data,
      address_of_raw_data,
      pointer_to_raw_data,
      pdb_path,
      pdb_age,
      pdb_guid,
    })
  }
  entries
}

///|
fn PEImage::read_codeview(
  self : Self,
  data_rva : UInt64,
  size : Int32,
) -> (String?, Int32?, String?) {
  let result = try {
    let offset = self.rva_to_offset(data_rva)
    ensure_range(self.data, offset, 4)
    if read_u8(self.data, offset) != 0x52 ||
      read_u8(self.data, offset + 1) != 0x53 ||
      read_u8(self.data, offset + 2) != 0x44 ||
      read_u8(self.data, offset + 3) != 0x53 {
      (None, None, None)
    } else if size >= 24 && offset + 24 <= self.data.length() {
      let age = checked_int(
        read_u32(self.data, offset + 20),
        offset + 20,
        "PDB age",
      )
      let guid = bytes_hex(self.data, offset + 4, 16)
      let path = read_ascii_z(self.data, offset + 24, size - 24)
      (Some(path), Some(age), Some(guid))
    } else {
      (None, None, None)
    }
  } catch {
    PeError(_, _) => (None, None, None)
  }
  result
}

///|
fn bytes_hex(data : Bytes, offset : Int32, length : Int32) -> String {
  let builder = StringBuilder()
  for index in 0..<length {
    let value = data[offset + index].to_int()
    builder.write_char(hex_digit(value >> 4))
    builder.write_char(hex_digit(value & 0xf))
  }
  builder.to_string()
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
fn debug_type_name(debug_type : Int32) -> String {
  match debug_type {
    1 => "coff"
    2 => "codeview"
    3 => "fpo"
    4 => "misc"
    5 => "exception"
    6 => "fixup"
    9 => "borland"
    10 => "reserved"
    11 => "clsid"
    12 => "vc-feature"
    13 => "pogo"
    14 => "iltcg"
    16 => "repro"
    17 => "exdll-characteristics"
    20 => "pdb-checksum"
    _ => "unknown"
  }
}
