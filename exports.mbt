// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::exports(self : Self) -> Array[ExportSymbol] raise PeError {
  let directory = match self.directory(0) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let offset = self.rva_to_offset(directory.virtual_address)
  if directory.size < 40 {
    raise PeError(offset, "export directory is truncated")
  }
  ensure_range(self.data, offset, 40)
  let name_rva = read_u32(self.data, offset + 12)
  let ordinal_base = read_u32(self.data, offset + 16)
  let number_of_functions = read_u32(self.data, offset + 20)
  let number_of_names = read_u32(self.data, offset + 24)
  let functions_rva = read_u32(self.data, offset + 28)
  let names_rva = read_u32(self.data, offset + 32)
  let ordinals_rva = read_u32(self.data, offset + 36)
  if name_rva == 0UL || number_of_names == 0UL || number_of_functions == 0UL {
    return []
  }
  let name_limit = if number_of_names < 8192UL {
    number_of_names.to_int()
  } else {
    8192
  }
  let function_limit = if number_of_functions < 65536UL {
    number_of_functions.to_int()
  } else {
    65536
  }
  let names_offset = self.rva_to_offset(names_rva)
  let ordinals_offset = self.rva_to_offset(ordinals_rva)
  let functions_offset = self.rva_to_offset(functions_rva)
  ensure_range(self.data, names_offset, name_limit * 4)
  ensure_range(self.data, ordinals_offset, name_limit * 2)
  ensure_range(self.data, functions_offset, function_limit * 4)
  let exports = []
  for index in 0..<name_limit {
    let symbol_name_rva = read_u32(self.data, names_offset + index * 4)
    let ordinal_index = read_u16(self.data, ordinals_offset + index * 2)
    if ordinal_index >= function_limit {
      continue
    }
    let function_rva = read_u32(self.data, functions_offset + ordinal_index * 4)
    if function_rva == 0UL {
      continue
    }
    let symbol_name = self.read_c_string(symbol_name_rva, 4096)
    let forwarder = if function_rva >= directory.virtual_address &&
      function_rva < directory.virtual_address + directory.size.to_uint64() {
      Some(self.read_c_string(function_rva, 4096))
    } else {
      None
    }
    exports.push({
      name: symbol_name,
      ordinal: ordinal_base.to_int() + ordinal_index,
      rva: function_rva,
      forwarder,
    })
  }
  exports
}
