// SPDX-License-Identifier: Apache-2.0

///|
fn fail_at(offset : Int32, message : String) -> Unit raise PeError {
  raise PeError(offset, message)
}

///|
fn ensure_range(
  data : Bytes,
  offset : Int32,
  length : Int32,
) -> Unit raise PeError {
  if offset < 0 || length < 0 || offset > data.length() - length {
    fail_at(offset, "read exceeds the available file data")
  }
}

///|
fn read_u8(data : Bytes, offset : Int32) -> Int32 raise PeError {
  ensure_range(data, offset, 1)
  data[offset].to_int()
}

///|
fn read_u16(data : Bytes, offset : Int32) -> Int32 raise PeError {
  ensure_range(data, offset, 2)
  data[offset].to_int() | (data[offset + 1].to_int() << 8)
}

///|
fn read_u32(data : Bytes, offset : Int32) -> UInt64 raise PeError {
  ensure_range(data, offset, 4)
  data[offset].to_int().to_uint64() |
  (data[offset + 1].to_int().to_uint64() << 8) |
  (data[offset + 2].to_int().to_uint64() << 16) |
  (data[offset + 3].to_int().to_uint64() << 24)
}

///|
fn read_u64(data : Bytes, offset : Int32) -> UInt64 raise PeError {
  ensure_range(data, offset, 8)
  read_u32(data, offset) | (read_u32(data, offset + 4) << 32)
}

///|
fn checked_int(
  value : UInt64,
  offset : Int32,
  field : String,
) -> Int32 raise PeError {
  if value > 0x7fffffffUL {
    fail_at(offset, "\{field} is too large for this tool")
  }
  value.to_int()
}

///|
fn read_ascii_z(
  data : Bytes,
  offset : Int32,
  max_length : Int32,
) -> String raise PeError {
  ensure_range(data, offset, 1)
  let builder = StringBuilder()
  let limit = if max_length < data.length() - offset {
    max_length
  } else {
    data.length() - offset
  }
  let mut index = 0
  while index < limit {
    let byte = data[offset + index].to_int()
    if byte == 0 {
      return builder.to_string()
    }
    if byte >= 0x20 && byte <= 0x7e {
      builder.write_char(byte.unsafe_to_char())
    } else {
      builder.write_char('.')
    }
    index = index + 1
  }
  builder.to_string()
}

///|
fn read_ascii_fixed(
  data : Bytes,
  offset : Int32,
  length : Int32,
) -> String raise PeError {
  ensure_range(data, offset, length)
  let builder = StringBuilder()
  let mut index = 0
  while index < length {
    let byte = data[offset + index].to_int()
    if byte == 0 {
      break
    }
    if byte >= 0x20 && byte <= 0x7e {
      builder.write_char(byte.unsafe_to_char())
    } else {
      builder.write_char('.')
    }
    index = index + 1
  }
  builder.to_string()
}
