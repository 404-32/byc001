// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::certificates(
  self : Self,
) -> Array[CertificateRecord] raise PeError {
  let directory = match self.directory(4) {
    Some(directory) if directory.virtual_address != 0UL && directory.size >= 8 =>
      directory
    _ => return []
  }
  let start = checked_int(
    directory.virtual_address,
    0,
    "certificate table file offset",
  )
  let end = start + directory.size
  ensure_range(self.data, start, directory.size)
  let records = []
  let mut offset = start
  while offset + 8 <= end && records.length() < 1024 {
    let length = checked_int(
      read_u32(self.data, offset),
      offset,
      "certificate length",
    )
    if length < 8 || offset + length > end {
      raise PeError(offset, "invalid WIN_CERTIFICATE length")
    }
    records.push({
      length,
      revision: read_u16(self.data, offset + 4),
      certificate_type: read_u16(self.data, offset + 6),
    })
    let aligned = (length + 7) / 8 * 8
    offset = offset + aligned
  }
  records
}

///|
pub fn certificate_type_name(certificate_type : Int32) -> String {
  match certificate_type {
    1 => "x509"
    2 => "pkcs-signed-data"
    3 => "reserved-1"
    4 => "ts-stack-signed"
    _ => "unknown"
  }
}
