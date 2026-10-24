// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::clr_header(self : Self) -> ClrHeaderInfo? raise PeError {
  let directory = match self.directory(14) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return None
  }
  let offset = self.rva_to_offset(directory.virtual_address)
  ensure_range(self.data, offset, 72)
  Some({
    header_size: checked_int(
      read_u32(self.data, offset),
      offset,
      "CLR header size",
    ),
    major_runtime_version: read_u16(self.data, offset + 4),
    minor_runtime_version: read_u16(self.data, offset + 6),
    metadata_rva: read_u32(self.data, offset + 8),
    metadata_size: checked_int(
      read_u32(self.data, offset + 12),
      offset + 12,
      "CLR metadata size",
    ),
    flags: checked_int(
      read_u32(self.data, offset + 16),
      offset + 16,
      "CLR flags",
    ),
    entry_point_token: checked_int(
      read_u32(self.data, offset + 20),
      offset + 20,
      "CLR entry-point token",
    ),
    resources_rva: read_u32(self.data, offset + 24),
    resources_size: checked_int(
      read_u32(self.data, offset + 28),
      offset + 28,
      "CLR resource size",
    ),
    strong_name_rva: read_u32(self.data, offset + 32),
    strong_name_size: checked_int(
      read_u32(self.data, offset + 36),
      offset + 36,
      "CLR strong-name size",
    ),
  })
}
