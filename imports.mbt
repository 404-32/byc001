///|
pub fn PEImage::imports(self : Self) -> Array[ImportLibrary] raise PeError {
  let directory = match self.directory(1) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let descriptor_offset = self.rva_to_offset(directory.virtual_address)
  let directory_limit = if directory.size >= 20 {
    directory.size / 20
  } else {
    4096
  }
  let descriptor_limit = if directory_limit < 4096 {
    directory_limit
  } else {
    4096
  }
  let libraries = []
  for index in 0..<descriptor_limit {
    let offset = descriptor_offset + index * 20
    ensure_range(self.data, offset, 20)
    let original_thunk = read_u32(self.data, offset)
    let timestamp = read_u32(self.data, offset + 4)
    let forwarder_chain = read_u32(self.data, offset + 8)
    let name_rva = read_u32(self.data, offset + 12)
    let first_thunk = read_u32(self.data, offset + 16)
    if original_thunk == 0UL &&
      timestamp == 0UL &&
      forwarder_chain == 0UL &&
      name_rva == 0UL &&
      first_thunk == 0UL {
      break
    }
    if name_rva == 0UL {
      continue
    }
    let name = self.read_c_string(name_rva, 4096)
    let thunk_rva = if original_thunk != 0UL {
      original_thunk
    } else {
      first_thunk
    }
    let symbols = self.import_symbols(thunk_rva)
    libraries.push({ name, symbols, })
  }
  libraries
}

///|
fn PEImage::import_symbols(
  self : Self,
  thunk_rva : UInt64,
) -> Array[ImportSymbol] raise PeError {
  if thunk_rva == 0UL {
    return []
  }
  let entry_size = if self.is_64_bit() { 8 } else { 4 }
  let symbols = []
  let mut index = 0
  while index < 65536 {
    let entry = if self.is_64_bit() {
      let offset = self.rva_to_offset(
        thunk_rva + (index * entry_size).to_uint64(),
      )
      read_u64(self.data, offset)
    } else {
      let offset = self.rva_to_offset(
        thunk_rva + (index * entry_size).to_uint64(),
      )
      read_u32(self.data, offset)
    }
    if entry == 0UL {
      break
    }
    let ordinal_mask = if self.is_64_bit() {
      0x8000000000000000UL
    } else {
      0x80000000UL
    }
    if entry.land(ordinal_mask) != 0UL {
      symbols.push({
        name: None,
        ordinal: Some(entry.land(0xffffUL).to_int()),
        hint: None,
      })
    } else {
      let name_rva = if self.is_64_bit() {
        entry.land(0x7fffffffffffffffUL)
      } else {
        entry.land(0x7fffffffUL)
      }
      let name_offset = self.rva_to_offset(name_rva)
      let hint = read_u16(self.data, name_offset)
      let name = read_ascii_z(self.data, name_offset + 2, 4096)
      symbols.push({ name: Some(name), ordinal: None, hint: Some(hint), })
    }
    index = index + 1
  }
  symbols
}
