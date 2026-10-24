// SPDX-License-Identifier: Apache-2.0

///|
/// Calculate and compare the PE optional-header checksum.
pub fn PEImage::checksum_info(self : Self) -> ChecksumInfo {
  let checksum_offset = self.pe_offset + 88
  let data = self.data
  let mut sum = 0UL
  let mut offset = 0
  while offset < data.length() {
    if offset >= checksum_offset && offset < checksum_offset + 4 {
      offset = offset + 2
      continue
    }
    let low = data[offset].to_int()
    let high = if offset + 1 < data.length() {
      data[offset + 1].to_int()
    } else {
      0
    }
    sum = sum + (low | (high << 8)).to_uint64()
    sum = sum.land(0xffffUL) + (sum >> 16)
    offset = offset + 2
  }
  sum = sum.land(0xffffUL) + (sum >> 16)
  sum = sum.land(0xffffUL) + (sum >> 16)
  let computed = (sum + data.length().to_uint64()).land(0xffffffffUL).to_int()
  let stored = self.checksum.to_int()
  { stored, computed, present: stored != 0, valid: stored == computed, }
}
