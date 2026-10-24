// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::exception_entries(
  self : Self,
) -> Array[ExceptionEntry] raise PeError {
  let directory = match self.directory(3) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let start = self.rva_to_offset(directory.virtual_address)
  ensure_range(self.data, start, directory.size)
  let entry_size = if directory.size % 12 == 0 {
    12
  } else if directory.size % 8 == 0 {
    8
  } else {
    raise PeError(start, "exception directory size is not aligned")
  }
  let count = directory.size / entry_size
  let limit = if count < 65536 { count } else { 65536 }
  let entries = []
  for index in 0..<limit {
    let offset = start + index * entry_size
    let begin_rva = read_u32(self.data, offset)
    let second = read_u32(self.data, offset + 4)
    if begin_rva == 0UL {
      continue
    }
    if entry_size == 12 {
      entries.push({
        begin_rva,
        end_rva: second,
        unwind_info_rva: read_u32(self.data, offset + 8),
      })
    } else {
      entries.push({ begin_rva, end_rva: 0UL, unwind_info_rva: second, })
    }
  }
  entries
}
