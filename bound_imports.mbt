///|
pub fn PEImage::bound_imports(self : Self) -> Array[BoundImport] raise PeError {
  let directory = match self.directory(11) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let start = self.rva_to_offset(directory.virtual_address)
  let end = start + directory.size
  ensure_range(self.data, start, directory.size)
  let imports = []
  let mut offset = start
  while offset + 8 <= end && imports.length() < 1024 {
    let timestamp_value = read_u32(self.data, offset)
    let name_offset = read_u16(self.data, offset + 4)
    let forwarder_count = read_u16(self.data, offset + 6)
    if timestamp_value == 0UL && name_offset == 0 && forwarder_count == 0 {
      break
    }
    if forwarder_count > 1024 {
      raise PeError(offset + 6, "bound-import forwarder count is too large")
    }
    let name = if name_offset > 0 && start + name_offset < self.data.length() {
      read_ascii_z(
        self.data,
        start + name_offset,
        self.data.length() - (start + name_offset),
      )
    } else {
      "<invalid-name>"
    }
    let forwarders = []
    let forwarder_offset = offset + 8
    ensure_range(self.data, forwarder_offset, forwarder_count * 8)
    for index in 0..<forwarder_count {
      let item_offset = forwarder_offset + index * 8
      let item_timestamp = read_u32(self.data, item_offset)
      let item_name_offset = read_u16(self.data, item_offset + 4)
      let item_name = if item_name_offset > 0 &&
        start + item_name_offset < self.data.length() {
        read_ascii_z(
          self.data,
          start + item_name_offset,
          self.data.length() - (start + item_name_offset),
        )
      } else {
        "<invalid-name>"
      }
      forwarders.push({
        name: item_name,
        timestamp: checked_int(item_timestamp, item_offset, "bound timestamp"),
      })
    }
    imports.push({
      name,
      timestamp: checked_int(timestamp_value, offset, "bound timestamp"),
      forwarders,
    })
    offset = forwarder_offset + forwarder_count * 8
  }
  imports
}
