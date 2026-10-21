///|
fn put_u16(buffer : Array[Byte], offset : Int32, value : Int32) -> Unit {
  buffer[offset] = value.to_byte()
  buffer[offset + 1] = (value >> 8).to_byte()
}

///|
fn put_u32(buffer : Array[Byte], offset : Int32, value : Int32) -> Unit {
  buffer[offset] = value.to_byte()
  buffer[offset + 1] = (value >> 8).to_byte()
  buffer[offset + 2] = (value >> 16).to_byte()
  buffer[offset + 3] = (value >> 24).to_byte()
}

///|
fn put_u64(buffer : Array[Byte], offset : Int32, value : UInt64) -> Unit {
  for index in 0..<8 {
    buffer[offset + index] = (value >> (index * 8)).to_int().to_byte()
  }
}

///|
fn put_ascii(buffer : Array[Byte], offset : Int32, text : String) -> Unit {
  let mut index = 0
  for char in text {
    buffer[offset + index] = char.to_int().to_byte()
    index = index + 1
  }
}

///|
fn build_pe32_array() -> Array[Byte] {
  let buffer = Array::make(0x400, b'\x00')
  buffer[0] = b'M'
  buffer[1] = b'Z'
  put_u32(buffer, 0x3c, 0x80)
  buffer[0x80] = b'P'
  buffer[0x81] = b'E'
  put_u16(buffer, 0x84, 0x014c)
  put_u16(buffer, 0x86, 1)
  put_u32(buffer, 0x88, 0x5f3759df)
  put_u16(buffer, 0x94, 0x00e0)
  put_u16(buffer, 0x96, 0x0102)
  let optional = 0x98
  put_u16(buffer, optional, 0x010b)
  put_u32(buffer, optional + 16, 0x1000)
  put_u32(buffer, optional + 20, 0x1000)
  put_u32(buffer, optional + 28, 0x400000)
  put_u32(buffer, optional + 32, 0x1000)
  put_u32(buffer, optional + 36, 0x200)
  put_u32(buffer, optional + 56, 0x2000)
  put_u32(buffer, optional + 60, 0x200)
  put_u16(buffer, optional + 68, 3)
  put_u16(buffer, optional + 70, 0x0140)
  put_u32(buffer, optional + 92, 16)
  let directories = optional + 96
  put_u32(buffer, directories, 0x1100)
  put_u32(buffer, directories + 4, 0x100)
  put_u32(buffer, directories + 8, 0x1080)
  put_u32(buffer, directories + 12, 40)
  let section = optional + 0xe0
  put_ascii(buffer, section, ".text")
  put_u32(buffer, section + 8, 0x200)
  put_u32(buffer, section + 12, 0x1000)
  put_u32(buffer, section + 16, 0x200)
  put_u32(buffer, section + 20, 0x200)
  put_u32(buffer, section + 36, 0x60000020)

  // Export directory at RVA 0x1100 (file offset 0x300).
  put_u32(buffer, 0x30c, 0x1140)
  put_u32(buffer, 0x310, 1)
  put_u32(buffer, 0x314, 1)
  put_u32(buffer, 0x318, 1)
  put_u32(buffer, 0x31c, 0x1160)
  put_u32(buffer, 0x320, 0x1164)
  put_u32(buffer, 0x324, 0x1168)
  put_ascii(buffer, 0x340, "sample.dll")
  put_u32(buffer, 0x360, 0x1000)
  put_u32(buffer, 0x364, 0x1170)
  put_u16(buffer, 0x368, 0)
  put_ascii(buffer, 0x370, "exported")

  // Import directory at RVA 0x1080 (file offset 0x280).
  put_u32(buffer, 0x280, 0x1180)
  put_u32(buffer, 0x28c, 0x11a0)
  put_u32(buffer, 0x290, 0x1188)
  put_u32(buffer, 0x380, 0x11b0)
  put_u32(buffer, 0x388, 0x11b0)
  put_ascii(buffer, 0x3a0, "KERNEL32.dll")
  put_u16(buffer, 0x3b0, 0)
  put_ascii(buffer, 0x3b2, "ExitProcess")
  buffer
}

///|
fn build_pe32_plus_array() -> Array[Byte] {
  let buffer = Array::make(0x400, b'\x00')
  buffer[0] = b'M'
  buffer[1] = b'Z'
  put_u32(buffer, 0x3c, 0x80)
  buffer[0x80] = b'P'
  buffer[0x81] = b'E'
  put_u16(buffer, 0x84, 0x8664)
  put_u16(buffer, 0x86, 1)
  put_u16(buffer, 0x94, 0x00f0)
  put_u16(buffer, 0x96, 0x0022)
  let optional = 0x98
  put_u16(buffer, optional, 0x020b)
  put_u32(buffer, optional + 16, 0x1000)
  put_u32(buffer, optional + 20, 0x1000)
  put_u64(buffer, optional + 24, 0x140000000UL)
  put_u32(buffer, optional + 32, 0x1000)
  put_u32(buffer, optional + 36, 0x200)
  put_u32(buffer, optional + 56, 0x2000)
  put_u32(buffer, optional + 60, 0x200)
  put_u16(buffer, optional + 68, 3)
  put_u16(buffer, optional + 70, 0x4140)
  put_u32(buffer, optional + 108, 0)
  let section = optional + 0xf0
  put_ascii(buffer, section, ".text")
  put_u32(buffer, section + 8, 0x200)
  put_u32(buffer, section + 12, 0x1000)
  put_u32(buffer, section + 16, 0x200)
  put_u32(buffer, section + 20, 0x200)
  put_u32(buffer, section + 36, 0x60000020)
  buffer
}

///|
test "parse PE32 headers and sections" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_array()))
  assert_true(image.format is PE32)
  assert_eq(image.machine, 0x014c)
  assert_eq(image.number_of_sections, 1)
  assert_eq(image.sections[0].name, ".text")
  assert_eq(image.rva_to_offset(0x1000), 0x200)
  assert_eq(image.rva_to_offset(0x1080), 0x280)
}

///|
test "parse imports" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_array()))
  let imports = image.imports()
  assert_eq(imports.length(), 1)
  assert_eq(imports[0].name, "KERNEL32.dll")
  assert_eq(imports[0].symbols.length(), 1)
  assert_eq(imports[0].symbols[0].name.unwrap(), "ExitProcess")
  assert_eq(imports[0].symbols[0].hint.unwrap(), 0)
}

///|
test "parse exports" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_array()))
  let exports = image.exports()
  assert_eq(exports.length(), 1)
  assert_eq(exports[0].name, "exported")
  assert_eq(exports[0].ordinal, 1)
  assert_eq(exports[0].rva, 0x1000UL)
  assert_true(exports[0].forwarder is None)
}

///|
test "parse export forwarders" {
  let bytes = build_pe32_array()
  put_u32(bytes, 0x360, 0x11d0)
  put_ascii(bytes, 0x3d0, "NTDLL.RtlExample")
  let image = PEImage::parse(Bytes::from_array(bytes))
  let exports = image.exports()
  assert_eq(exports[0].forwarder.unwrap(), "NTDLL.RtlExample")
}

///|
test "parse ordinal imports" {
  let bytes = build_pe32_array()
  bytes[0x380] = (5).to_byte()
  bytes[0x381] = (0).to_byte()
  bytes[0x382] = (0).to_byte()
  bytes[0x383] = (0x80).to_byte()
  bytes[0x388] = (5).to_byte()
  bytes[0x389] = (0).to_byte()
  bytes[0x38a] = (0).to_byte()
  bytes[0x38b] = (0x80).to_byte()
  let image = PEImage::parse(Bytes::from_array(bytes))
  let symbol = image.imports()[0].symbols[0]
  assert_true(symbol.name is None)
  assert_eq(symbol.ordinal.unwrap(), 5)
}

///|
test "parse PE32 plus metadata" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_plus_array()))
  assert_true(image.format is PE32Plus)
  assert_eq(image.machine, 0x8664)
  assert_eq(image.image_base, 0x140000000UL)
  assert_true(image.is_64_bit())
}

///|
test "RVA mapping rejects uninitialized section bytes" {
  let bytes = build_pe32_array()
  put_u32(bytes, 0x98 + 0xe0 + 8, 0x400)
  let image = PEImage::parse(Bytes::from_array(bytes))
  let error_offset = try {
    let _ = image.rva_to_offset(0x1200)
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(error_offset, Some(0x200))
}

///|
test "security diagnostics detect hardening flags and RWX" {
  let bytes = build_pe32_array()
  put_u16(bytes, 0x98 + 70, 0)
  put_u32(bytes, 0x98 + 0xe0 + 36, 0xe0000020)
  let image = PEImage::parse(Bytes::from_array(bytes))
  let diagnostics = image.security_diagnostics()
  let mut saw_rwx = false
  let mut saw_no_aslr = false
  let mut saw_unsigned = false
  for diagnostic in diagnostics {
    if diagnostic.code == "pe.rwx-section" {
      saw_rwx = true
    }
    if diagnostic.code == "pe.no-aslr" {
      saw_no_aslr = true
    }
    if diagnostic.code == "pe.unsigned" {
      saw_unsigned = true
    }
  }
  assert_true(saw_rwx)
  assert_true(saw_no_aslr)
  assert_true(saw_unsigned)
}

///|
test "truncated and invalid files return offset errors" {
  let truncated = try {
    let _ = PEImage::parse(b"MZ")
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(truncated, Some(0))
  let bytes = build_pe32_array()
  put_u32(bytes, 0x3c, 0x7fffffff)
  let invalid = try {
    let _ = PEImage::parse(Bytes::from_array(bytes))
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(invalid, Some(0x7fffffff))
}
