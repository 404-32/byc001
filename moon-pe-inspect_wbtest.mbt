// SPDX-License-Identifier: Apache-2.0

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
  let buffer = Array::make(0x1020, b'\x00')
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
  put_u32(buffer, optional + 56, 0x3000)
  put_u32(buffer, optional + 60, 0x200)
  put_u16(buffer, optional + 68, 3)
  put_u16(buffer, optional + 70, 0x0140)
  put_u32(buffer, optional + 92, 16)
  let directories = optional + 96
  put_u32(buffer, directories, 0x1100)
  put_u32(buffer, directories + 4, 0x100)
  put_u32(buffer, directories + 8, 0x1080)
  put_u32(buffer, directories + 12, 40)
  put_u32(buffer, directories + 16, 0x1200)
  put_u32(buffer, directories + 20, 0x100)
  put_u32(buffer, directories + 24, 0x1700)
  put_u32(buffer, directories + 28, 12)
  put_u32(buffer, directories + 32, 0xd00)
  put_u32(buffer, directories + 36, 16)
  put_u32(buffer, directories + 40, 0x1300)
  put_u32(buffer, directories + 44, 12)
  put_u32(buffer, directories + 48, 0x1400)
  put_u32(buffer, directories + 52, 28)
  put_u32(buffer, directories + 72, 0x1500)
  put_u32(buffer, directories + 76, 24)
  put_u32(buffer, directories + 80, 0x1600)
  put_u32(buffer, directories + 84, 92)
  put_u32(buffer, directories + 88, 0x1900)
  put_u32(buffer, directories + 92, 40)
  put_u32(buffer, directories + 104, 0x1800)
  put_u32(buffer, directories + 108, 64)
  put_u32(buffer, directories + 112, 0x1a00)
  put_u32(buffer, directories + 116, 72)
  let section = optional + 0xe0
  put_ascii(buffer, section, ".text")
  put_u32(buffer, section + 8, 0xc00)
  put_u32(buffer, section + 12, 0x1000)
  put_u32(buffer, section + 16, 0xe00)
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

  // Resource directory: RCDATA/101/1033.
  put_u16(buffer, 0x40c, 0)
  put_u16(buffer, 0x40e, 1)
  put_u32(buffer, 0x410, 10)
  put_u32(buffer, 0x414, 0x80000018)
  put_u16(buffer, 0x424, 0)
  put_u16(buffer, 0x426, 1)
  put_u32(buffer, 0x428, 101)
  put_u32(buffer, 0x42c, 0x80000030)
  put_u16(buffer, 0x43c, 0)
  put_u16(buffer, 0x43e, 1)
  put_u32(buffer, 0x440, 1033)
  put_u32(buffer, 0x444, 0x50)
  put_u32(buffer, 0x450, 0x12a0)
  put_u32(buffer, 0x454, 4)
  put_u32(buffer, 0x458, 0)
  put_ascii(buffer, 0x4a0, "DATA")

  // Base relocations.
  put_u32(buffer, 0x500, 0x1000)
  put_u32(buffer, 0x504, 12)
  put_u16(buffer, 0x508, 0x3004)
  put_u16(buffer, 0x50a, 0)

  // CodeView debug entry.
  put_u32(buffer, 0x60c, 2)
  put_u32(buffer, 0x610, 32)
  put_u32(buffer, 0x614, 0x1460)
  put_u32(buffer, 0x618, 0x660)
  put_ascii(buffer, 0x660, "RSDS")
  for index in 0..<16 {
    buffer[0x664 + index] = (index + 1).to_byte()
  }
  put_u32(buffer, 0x674, 7)
  put_ascii(buffer, 0x678, "app.pdb")

  // TLS directory and one callback.
  put_u32(buffer, 0x700, 0x401040)
  put_u32(buffer, 0x704, 0x401044)
  put_u32(buffer, 0x708, 0x402000)
  put_u32(buffer, 0x70c, 0x401760)
  put_u32(buffer, 0x710, 4)
  put_u32(buffer, 0x714, 0)
  put_u32(buffer, 0x960, 0x401000)
  put_u32(buffer, 0x964, 0)

  // PE32 load-config directory.
  put_u32(buffer, 0x800, 92)
  put_u32(buffer, 0x804, 123)
  put_u32(buffer, 0x80c, 0)
  put_u32(buffer, 0x810, 0)
  put_u32(buffer, 0x83c, 0x401760)
  put_u32(buffer, 0x848, 0x401760)
  put_u32(buffer, 0x850, 0x401000)
  put_u32(buffer, 0x854, 2)
  put_u32(buffer, 0x858, 0x100)

  // x64-style exception entry.
  put_u32(buffer, 0x900, 0x1000)
  put_u32(buffer, 0x904, 0x1010)
  put_u32(buffer, 0x908, 0x1750)

  // Delay import descriptor and thunks.
  put_u32(buffer, 0xa00, 1)
  put_u32(buffer, 0xa04, 0x1a70)
  put_u32(buffer, 0xa0c, 0x1a88)
  put_u32(buffer, 0xa10, 0x1a90)
  put_u32(buffer, 0xa1c, 456)
  put_ascii(buffer, 0xc70, "USER32.dll")
  put_u32(buffer, 0xc88, 0x1aa0)
  put_u32(buffer, 0xc8c, 0)
  put_u32(buffer, 0xc90, 0x1aa0)
  put_u32(buffer, 0xc94, 0)
  put_u16(buffer, 0xca0, 0)
  put_ascii(buffer, 0xca2, "MessageBoxW")

  // Bound import directory.
  put_u32(buffer, 0xb00, 456)
  put_u16(buffer, 0xb04, 0x28)
  put_u16(buffer, 0xb06, 1)
  put_u32(buffer, 0xb08, 789)
  put_u16(buffer, 0xb0c, 0x38)
  put_ascii(buffer, 0xb28, "KERNEL32.dll")
  put_ascii(buffer, 0xb38, "NTDLL.dll")

  // Minimal CLR/.NET header.
  put_u32(buffer, 0xc00, 72)
  put_u16(buffer, 0xc04, 2)
  put_u16(buffer, 0xc06, 5)
  put_u32(buffer, 0xc08, 0x1a50)
  put_u32(buffer, 0xc0c, 8)
  put_u32(buffer, 0xc10, 1)
  put_u32(buffer, 0xc14, 0x06000001)

  // Authenticode certificate record.
  put_u32(buffer, 0xd00, 16)
  put_u16(buffer, 0xd04, 0x0200)
  put_u16(buffer, 0xd06, 2)

  // Data after the final section is reported as overlay.
  put_ascii(buffer, 0x1000, "OVERLAY")
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
fn build_coff_object_array() -> Array[Byte] {
  let buffer = Array::make(0x100, b'\x00')
  put_u16(buffer, 0, 0x014c)
  put_u16(buffer, 2, 1)
  put_u32(buffer, 4, 987)
  put_u32(buffer, 8, 0x80)
  put_u32(buffer, 12, 3)
  put_u16(buffer, 16, 0)
  put_u16(buffer, 18, 0x0004)

  put_ascii(buffer, 20, ".text")
  put_u32(buffer, 28, 4)
  put_u32(buffer, 32, 0)
  put_u32(buffer, 36, 4)
  put_u32(buffer, 40, 0x60)
  put_u32(buffer, 56, 0x60000020)
  put_ascii(buffer, 0x60, "CODE")

  // Short symbol, one auxiliary record, then a long-name symbol.
  put_ascii(buffer, 0x80, "func")
  put_u32(buffer, 0x88, 0)
  put_u16(buffer, 0x8c, 1)
  put_u16(buffer, 0x8e, 0x20)
  buffer[0x90] = (2).to_byte()
  buffer[0x91] = (1).to_byte()

  put_u32(buffer, 0xa8, 4)
  put_u32(buffer, 0xac, 0)
  put_u16(buffer, 0xb0, 1)
  put_u16(buffer, 0xb2, 0)
  buffer[0xb4] = (2).to_byte()
  buffer[0xb5] = (0).to_byte()

  put_u32(buffer, 0xb6, 16)
  put_ascii(buffer, 0xba, "long_symbol")
  buffer
}

///|
fn build_rich_pe_array() -> Array[Byte] {
  let buffer = Array::make(0x200, b'\x00')
  buffer[0] = b'M'
  buffer[1] = b'Z'
  put_u32(buffer, 0x3c, 0x100)
  let key = 0x12345678
  put_u32(buffer, 0x80, key ^ 0x536e6144)
  put_u32(buffer, 0x84, key)
  put_u32(buffer, 0x88, key)
  put_u32(buffer, 0x8c, key)
  put_u32(buffer, 0x90, key ^ 0x00011234)
  put_u32(buffer, 0x94, key ^ 3)
  put_ascii(buffer, 0x98, "Rich")
  put_u32(buffer, 0x9c, key)

  buffer[0x100] = b'P'
  buffer[0x101] = b'E'
  put_u16(buffer, 0x104, 0x014c)
  put_u16(buffer, 0x106, 0)
  put_u16(buffer, 0x114, 96)
  put_u16(buffer, 0x116, 0x0102)
  let optional = 0x118
  put_u16(buffer, optional, 0x010b)
  put_u32(buffer, optional + 28, 0x400000)
  put_u32(buffer, optional + 32, 0x1000)
  put_u32(buffer, optional + 36, 0x200)
  put_u32(buffer, optional + 56, 0x1000)
  put_u32(buffer, optional + 60, 0x200)
  put_u16(buffer, optional + 68, 3)
  put_u32(buffer, optional + 92, 0)
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
test "parse Rich header and section entropy" {
  let rich_image = PEImage::parse(Bytes::from_array(build_rich_pe_array()))
  let rich = rich_image.rich_header().unwrap()
  assert_eq(rich.entries.length(), 1)
  assert_eq(rich.entries[0].product_id, 1)
  assert_eq(rich.entries[0].build_id, 0x1234)
  assert_eq(rich.entries[0].use_count, 3)

  let entropy_bytes = Array::make(512, b'\x00')
  for index in 0..<512 {
    entropy_bytes[index] = (index % 256).to_byte()
  }
  let entropy = shannon_entropy(Bytes::from_array(entropy_bytes), 0, 512)
  assert_true(entropy > 7.99 && entropy <= 8.0)
}

///|
test "parse standalone COFF object sections and symbols" {
  let object = CoffObject::parse(Bytes::from_array(build_coff_object_array()))
  assert_eq(object.machine, 0x014c)
  assert_eq(object.section_count, 1)
  assert_eq(object.sections[0].name, ".text")
  assert_eq(object.sections[0].raw_size, 4)
  assert_eq(object.symbols.length(), 2)
  assert_eq(object.symbols[0].name, "func")
  assert_eq(object.symbols[1].name, "long_symbol")
  assert_eq(object.symbols[1].section_number, 1)
}

///|
test "COFF parser rejects out-of-range section data" {
  let bytes = build_coff_object_array()
  put_u32(bytes, 40, 0x200)
  let error_offset = try {
    let _ = CoffObject::parse(Bytes::from_array(bytes))
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(error_offset, Some(0x200))
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
  put_u32(bytes, 0x98 + 0xe0 + 8, 0x1000)
  let image = PEImage::parse(Bytes::from_array(bytes))
  let error_offset = try {
    let _ = image.rva_to_offset(0x1f00)
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
  let mut saw_certificate = false
  for diagnostic in diagnostics {
    if diagnostic.code == "pe.rwx-section" {
      saw_rwx = true
    }
    if diagnostic.code == "pe.no-aslr" {
      saw_no_aslr = true
    }
    if diagnostic.code == "pe.certificate-table" {
      saw_certificate = true
    }
  }
  assert_true(saw_rwx)
  assert_true(saw_no_aslr)
  assert_true(saw_certificate)
}

///|
test "parse resource tree" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_array()))
  let resources = image.resources()
  assert_eq(resources.length(), 1)
  assert_eq(resources[0].path, "rcdata/#101/#1033")
  assert_eq(resources[0].data_rva, 0x12a0UL)
  assert_eq(resources[0].file_offset.unwrap(), 0x4a0)
  assert_eq(resources[0].size, 4)
}

///|
test "parse relocation delay import TLS debug load-config and exceptions" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_array()))
  let relocations = image.base_relocations()
  assert_eq(relocations.length(), 1)
  assert_eq(relocations[0].entries[0].relocation_type, 3)
  assert_eq(relocations[0].entries[0].target_rva, 0x1004UL)

  let delays = image.delay_imports()
  assert_eq(delays.length(), 1)
  assert_eq(delays[0].name, "USER32.dll")
  assert_eq(delays[0].symbols[0].name.unwrap(), "MessageBoxW")

  let tls = image.tls().unwrap()
  assert_eq(tls.raw_data_start, 0x401040UL)
  assert_eq(tls.callbacks.length(), 1)
  assert_eq(tls.callbacks[0], 0x401000UL)

  let debug = image.debug_entries()
  assert_eq(debug.length(), 1)
  assert_eq(debug[0].type_name, "codeview")
  assert_eq(debug[0].pdb_path.unwrap(), "app.pdb")
  assert_eq(debug[0].pdb_age.unwrap(), 7)

  let config = image.load_config().unwrap()
  assert_eq(config.structure_size, 92)
  assert_eq(config.guard_flags.unwrap(), 0x100)
  assert_eq(config.guard_cf_function_count.unwrap(), 2)
  assert_eq(config.security_cookie.unwrap(), 0x401760UL)

  let exceptions = image.exception_entries()
  assert_eq(exceptions.length(), 1)
  assert_eq(exceptions[0].begin_rva, 0x1000UL)
  assert_eq(exceptions[0].unwind_info_rva, 0x1750UL)
}

///|
test "artifact diff reports metadata sections and hardening changes" {
  let first = PEImage::parse(Bytes::from_array(build_pe32_array()))
  let bytes = build_pe32_array()
  put_u16(bytes, 0x98 + 70, 0)
  put_u32(bytes, 0x98 + 0xe0 + 36, 0xe0000020)
  let second = PEImage::parse(Bytes::from_array(bytes))
  let changes = first.diff(second)
  let mut saw_flags = false
  let mut saw_sections = false
  for change in changes {
    if change.field == "dll-characteristics" {
      saw_flags = true
    }
    if change.field == "sections" {
      saw_sections = true
    }
  }
  assert_true(saw_flags)
  assert_true(saw_sections)
}

///|
test "parse bound imports CLR certificate and overlay" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_array()))
  let bound = image.bound_imports()
  assert_eq(bound.length(), 1)
  assert_eq(bound[0].name, "KERNEL32.dll")
  assert_eq(bound[0].forwarders[0].name, "NTDLL.dll")

  let clr = image.clr_header().unwrap()
  assert_eq(clr.header_size, 72)
  assert_eq(clr.metadata_rva, 0x1a50UL)
  assert_eq(clr.metadata_size, 8)
  assert_eq(clr.entry_point_token, 0x06000001)

  let certificates = image.certificates()
  assert_eq(certificates.length(), 1)
  assert_eq(certificates[0].certificate_type, 2)
  assert_eq(certificate_type_name(2), "pkcs-signed-data")

  let overlay = image.overlay().unwrap()
  assert_eq(overlay.offset, 0x1000)
  assert_eq(overlay.size, 0x20)
}

///|
test "calculate and validate PE checksum" {
  let bytes = build_pe32_array()
  let initial = PEImage::parse(Bytes::from_array(bytes))
  let initial_checksum = initial.checksum_info()
  assert_true(!initial_checksum.present)
  put_u32(bytes, 0xd8, initial_checksum.computed)
  let image = PEImage::parse(Bytes::from_array(bytes))
  let checksum = image.checksum_info()
  assert_true(checksum.present)
  assert_true(checksum.valid)
  assert_eq(checksum.stored, checksum.computed)
}

///|
test "checksum mismatch appears in security diagnostics" {
  let bytes = build_pe32_array()
  put_u32(bytes, 0xd8, 1)
  let image = PEImage::parse(Bytes::from_array(bytes))
  let diagnostics = image.security_diagnostics()
  let mut mismatch = false
  for diagnostic in diagnostics {
    if diagnostic.code == "pe.checksum-mismatch" {
      mismatch = true
    }
  }
  assert_true(mismatch)
}

///|
test "absent directories return empty optional values" {
  let image = PEImage::parse(Bytes::from_array(build_pe32_plus_array()))
  assert_eq(image.resources().length(), 0)
  assert_eq(image.base_relocations().length(), 0)
  assert_eq(image.delay_imports().length(), 0)
  assert_eq(image.debug_entries().length(), 0)
  assert_eq(image.exception_entries().length(), 0)
  assert_eq(image.bound_imports().length(), 0)
  assert_eq(image.certificates().length(), 0)
  assert_true(image.tls() is None)
  assert_true(image.clr_header() is None)
  assert_true(image.load_config() is None)
  assert_true(image.overlay() is None)
}

///|
test "malformed optional directories return bounded errors" {
  let certificate_bytes = build_pe32_array()
  put_u32(certificate_bytes, 0xd00, 4)
  let certificate_error = try {
    let image = PEImage::parse(Bytes::from_array(certificate_bytes))
    let _ = image.certificates()
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(certificate_error, Some(0xd00))

  let relocation_bytes = build_pe32_array()
  put_u32(relocation_bytes, 0x504, 2)
  let relocation_error = try {
    let image = PEImage::parse(Bytes::from_array(relocation_bytes))
    let _ = image.base_relocations()
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(relocation_error, Some(0x500))

  let bound_bytes = build_pe32_array()
  put_u16(bound_bytes, 0xb06, 2000)
  let bound_error = try {
    let image = PEImage::parse(Bytes::from_array(bound_bytes))
    let _ = image.bound_imports()
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(bound_error, Some(0xb06))
}

///|
test "header RVA and short import directory stay bounded" {
  let header_bytes = build_pe32_array()
  put_u32(header_bytes, 0x98 + 60, 0x2000)
  let header_error = try {
    let image = PEImage::parse(Bytes::from_array(header_bytes))
    let _ = image.rva_to_offset(0x1fff)
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(header_error, Some(0x1fff))

  let import_bytes = build_pe32_array()
  put_u32(import_bytes, 0x98 + 96 + 12, 4)
  let import_error = try {
    let image = PEImage::parse(Bytes::from_array(import_bytes))
    let _ = image.imports()
    None
  } catch {
    PeError(offset, _) => Some(offset)
  }
  assert_eq(import_error, Some(0x280))
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
