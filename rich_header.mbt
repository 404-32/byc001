// SPDX-License-Identifier: Apache-2.0

///|
/// Decode the optional Rich Header located between the DOS stub and PE header.
pub fn PEImage::rich_header(self : Self) -> RichHeaderInfo? {
  let rich_offset = find_rich_marker(self.data, self.pe_offset)
  if rich_offset < 0 {
    return None
  }
  let key = read_u32(self.data, rich_offset + 4) catch {
    PeError(_, _) => return None
  }
  let dans_value = 0x536e6144UL
  let mut offset = 0x40
  let mut dans_offset = -1
  while offset + 4 <= rich_offset {
    let value = read_u32(self.data, offset) catch {
      PeError(_, _) => return None
    }
    if value.lxor(key) == dans_value {
      dans_offset = offset
      break
    }
    offset = offset + 4
  }
  if dans_offset < 0 || dans_offset + 16 > rich_offset {
    return None
  }
  let entries = []
  let mut index_offset = dans_offset + 16
  while index_offset + 8 <= rich_offset && entries.length() < 256 {
    let combined = (read_u32(self.data, index_offset) catch {
      PeError(_, _) => return None
    }).lxor(key)
    let count = (read_u32(self.data, index_offset + 4) catch {
      PeError(_, _) => return None
    }).lxor(key)
    let product_id = (combined >> 16).to_int()
    let build_id = combined.land(0xffffUL).to_int()
    entries.push({ product_id, build_id, use_count: count.to_int(), })
    index_offset = index_offset + 8
  }
  Some({ xor_key: key, entries, })
}

///|
fn find_rich_marker(data : Bytes, pe_offset : Int32) -> Int32 {
  let mut offset = 0x40
  while offset + 8 <= pe_offset {
    if data[offset] == b'R' &&
      data[offset + 1] == b'i' &&
      data[offset + 2] == b'c' &&
      data[offset + 3] == b'h' {
      return offset
    }
    offset = offset + 4
  }
  -1
}
