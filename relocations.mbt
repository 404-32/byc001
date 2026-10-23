///|
pub fn PEImage::base_relocations(
  self : Self,
) -> Array[RelocationBlock] raise PeError {
  let directory = match self.directory(5) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let start = self.rva_to_offset(directory.virtual_address)
  let end = start + directory.size
  ensure_range(self.data, start, directory.size)
  let blocks = []
  let mut offset = start
  while offset + 8 <= end && blocks.length() < 8192 {
    let page_rva = read_u32(self.data, offset)
    let block_size = checked_int(
      read_u32(self.data, offset + 4),
      offset + 4,
      "relocation block size",
    )
    if page_rva == 0UL && block_size == 0 {
      break
    }
    if block_size < 8 || block_size % 4 != 0 || offset + block_size > end {
      raise PeError(offset, "invalid base relocation block size")
    }
    let entries = []
    let mut entry_offset = offset + 8
    while entry_offset < offset + block_size {
      let value = read_u16(self.data, entry_offset)
      let relocation_type = value >> 12
      let relocation_offset = value & 0x0fff
      if relocation_type != 0 {
        entries.push({
          relocation_type,
          offset: relocation_offset,
          target_rva: page_rva + relocation_offset.to_uint64(),
        })
      }
      entry_offset = entry_offset + 2
    }
    blocks.push({ page_rva, entries, })
    offset = offset + block_size
  }
  blocks
}

///|
pub fn relocation_type_name(relocation_type : Int32) -> String {
  match relocation_type {
    1 => "high"
    2 => "low"
    3 => "high-low"
    4 => "high-adj"
    5 => "mips-jump"
    7 => "thumb-mov32"
    9 => "mips-jump16"
    10 => "dir64"
    _ => "unknown"
  }
}
