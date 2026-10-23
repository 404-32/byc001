///|
pub fn PEImage::tls(self : Self) -> TlsInfo? raise PeError {
  let directory = match self.directory(9) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return None
  }
  let offset = self.rva_to_offset(directory.virtual_address)
  let minimum_size = if self.is_64_bit() { 40 } else { 24 }
  ensure_range(self.data, offset, minimum_size)
  let pointer_size = if self.is_64_bit() { 8 } else { 4 }
  let raw_start = self.read_pointer(offset)
  let raw_end = self.read_pointer(offset + pointer_size)
  let index_address = self.read_pointer(offset + pointer_size * 2)
  let callbacks_address = self.read_pointer(offset + pointer_size * 3)
  let size_offset = offset + pointer_size * 4
  let size_of_zero_fill = checked_int(
    read_u32(self.data, size_offset),
    size_offset,
    "TLS zero-fill size",
  )
  let characteristics = checked_int(
    read_u32(self.data, size_offset + 4),
    size_offset + 4,
    "TLS characteristics",
  )
  let callbacks = []
  if callbacks_address != 0UL {
    match self.va_to_rva(callbacks_address) {
      Some(callback_rva) => {
        let callback_offset = self.rva_to_offset(callback_rva)
        let mut index = 0
        while index < 128 {
          let entry_offset = callback_offset + index * pointer_size
          if entry_offset + pointer_size > self.data.length() {
            break
          }
          let callback = self.read_pointer(entry_offset)
          if callback == 0UL {
            break
          }
          callbacks.push(callback)
          index = index + 1
        }
      }
      None => ()
    }
  }
  Some({
    raw_data_start: raw_start,
    raw_data_end: raw_end,
    index_address,
    callbacks_address,
    size_of_zero_fill,
    characteristics,
    callbacks,
  })
}

///|
fn PEImage::read_pointer(self : Self, offset : Int32) -> UInt64 raise PeError {
  if self.is_64_bit() {
    read_u64(self.data, offset)
  } else {
    read_u32(self.data, offset)
  }
}
