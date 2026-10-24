// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::overlay(self : Self) -> OverlayInfo? {
  let mut max_end = self.size_of_headers
  for section in self.sections {
    let end = section.raw_offset + section.raw_size
    if end > max_end {
      max_end = end
    }
  }
  match self.directory(4) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      if directory.virtual_address <= 0x7fffffffUL {
        let end = directory.virtual_address.to_int() + directory.size
        if end > max_end {
          max_end = end
        }
      }
    _ => ()
  }
  if max_end < self.data.length() {
    Some({ offset: max_end, size: self.data.length() - max_end, })
  } else {
    None
  }
}
