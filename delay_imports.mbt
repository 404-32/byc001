// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::delay_imports(
  self : Self,
) -> Array[DelayImportLibrary] raise PeError {
  let directory = match self.directory(13) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let start = self.rva_to_offset(directory.virtual_address)
  let limit = if directory.size >= 32 { directory.size / 32 } else { 4096 }
  let descriptor_limit = if limit < 4096 { limit } else { 4096 }
  let libraries = []
  for index in 0..<descriptor_limit {
    let offset = start + index * 32
    ensure_range(self.data, offset, 32)
    let attributes_value = read_u32(self.data, offset)
    let name_value = read_u32(self.data, offset + 4)
    let module_handle = read_u32(self.data, offset + 8)
    let iat = read_u32(self.data, offset + 12)
    let names = read_u32(self.data, offset + 16)
    let bound_iat = read_u32(self.data, offset + 20)
    let unload_info = read_u32(self.data, offset + 24)
    let timestamp = read_u32(self.data, offset + 28)
    if attributes_value == 0UL &&
      name_value == 0UL &&
      module_handle == 0UL &&
      iat == 0UL &&
      names == 0UL &&
      bound_iat == 0UL &&
      unload_info == 0UL &&
      timestamp == 0UL {
      break
    }
    let attributes = attributes_value.to_int()
    let name_rva = self.delay_field_rva(name_value, attributes)
    if name_rva == 0UL {
      continue
    }
    let name = self.read_c_string(name_rva, 4096)
    let names_rva = self.delay_field_rva(names, attributes)
    let symbols = self.import_symbols(names_rva)
    libraries.push({
      name,
      attributes,
      timestamp: checked_int(timestamp, offset + 28, "delay-import timestamp"),
      symbols,
    })
  }
  libraries
}

///|
fn PEImage::delay_field_rva(
  self : Self,
  value : UInt64,
  attributes : Int32,
) -> UInt64 raise PeError {
  if value == 0UL || (attributes & 1) != 0 {
    return value
  }
  match self.va_to_rva(value) {
    Some(rva) => rva
    None => raise PeError(0, "delay-import VA is outside the image")
  }
}
