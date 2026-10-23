///|
pub fn PEImage::load_config(self : Self) -> LoadConfigInfo? raise PeError {
  let directory = match self.directory(10) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return None
  }
  let offset = self.rva_to_offset(directory.virtual_address)
  let mut available = directory.size
  let file_available = self.data.length() - offset
  if available > file_available {
    available = file_available
  }
  if available < 4 {
    raise PeError(offset, "load-config directory is truncated")
  }
  let declared_size = checked_int(
    read_u32(self.data, offset),
    offset,
    "load-config structure size",
  )
  if declared_size >= 4 && declared_size < available {
    available = declared_size
  }
  let timestamp = read_u32_field(self.data, offset, available, 4)
  let global_flags_clear = read_u32_field(self.data, offset, available, 12)
  let global_flags_set = read_u32_field(self.data, offset, available, 16)
  let (
    cookie_offset,
    se_table_offset,
    se_count_offset,
    guard_check_offset,
    guard_dispatch_offset,
    guard_table_offset,
    guard_count_offset,
    guard_flags_offset,
  ) = if self.is_64_bit() {
    (88, 96, 104, 112, 120, 128, 136, 144)
  } else {
    (60, 64, 68, 72, 76, 80, 84, 88)
  }
  Some({
    structure_size: declared_size,
    timestamp: match timestamp {
      Some(value) => value
      None => 0
    },
    global_flags_clear,
    global_flags_set,
    security_cookie: read_pointer_field(
      self.data,
      offset,
      available,
      cookie_offset,
      self.is_64_bit(),
    ),
    se_handler_table: read_pointer_field(
      self.data,
      offset,
      available,
      se_table_offset,
      self.is_64_bit(),
    ),
    se_handler_count: read_pointer_count_field(
      self.data,
      offset,
      available,
      se_count_offset,
      self.is_64_bit(),
    ),
    guard_cf_check_pointer: read_pointer_field(
      self.data,
      offset,
      available,
      guard_check_offset,
      self.is_64_bit(),
    ),
    guard_cf_dispatch_pointer: read_pointer_field(
      self.data,
      offset,
      available,
      guard_dispatch_offset,
      self.is_64_bit(),
    ),
    guard_cf_function_table: read_pointer_field(
      self.data,
      offset,
      available,
      guard_table_offset,
      self.is_64_bit(),
    ),
    guard_cf_function_count: read_pointer_count_field(
      self.data,
      offset,
      available,
      guard_count_offset,
      self.is_64_bit(),
    ),
    guard_flags: read_u32_field(
      self.data,
      offset,
      available,
      guard_flags_offset,
    ),
  })
}

///|
fn read_u32_field(
  data : Bytes,
  start : Int32,
  available : Int32,
  relative_offset : Int32,
) -> Int32? {
  if relative_offset + 4 > available {
    return None
  }
  let result = Some(
    checked_int(
      read_u32(data, start + relative_offset),
      start + relative_offset,
      "load-config field",
    ),
  ) catch {
    PeError(_, _) => None
  }
  result
}

///|
fn read_pointer_field(
  data : Bytes,
  start : Int32,
  available : Int32,
  relative_offset : Int32,
  is_64_bit : Bool,
) -> UInt64? {
  let width = if is_64_bit { 8 } else { 4 }
  if relative_offset + width > available {
    return None
  }
  try {
    if is_64_bit {
      Some(read_u64(data, start + relative_offset))
    } else {
      Some(read_u32(data, start + relative_offset))
    }
  } catch {
    PeError(_, _) => None
  }
}

///|
fn read_pointer_count_field(
  data : Bytes,
  start : Int32,
  available : Int32,
  relative_offset : Int32,
  is_64_bit : Bool,
) -> Int32? {
  let value = read_pointer_field(
    data, start, available, relative_offset, is_64_bit,
  )
  match value {
    Some(count) if count <= 0x7fffffffUL => Some(count.to_int())
    _ => None
  }
}
