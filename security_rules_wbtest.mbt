// SPDX-License-Identifier: Apache-2.0

///|
fn diagnostic_codes(buffer : Array[Byte]) -> Array[String] {
  let image = PEImage::parse(Bytes::from_array(buffer)) catch {
    PeError(_, _) => abort("security fixture failed to parse")
  }
  let codes = []
  for diagnostic in image.security_diagnostics() {
    codes.push(diagnostic.code)
  }
  codes
}

///|
fn assert_diagnostic(buffer : Array[Byte], code : String) -> Unit raise Error {
  assert_true(diagnostic_codes(buffer).contains(code))
}

///|
fn assert_no_diagnostic(
  buffer : Array[Byte],
  code : String,
) -> Unit raise Error {
  assert_true(!diagnostic_codes(buffer).contains(code))
}

///|
test "security matrix baseline has independent hardening observations" {
  let codes = diagnostic_codes(build_pe32_array())
  assert_true(codes.contains("pe.no-cfg"))
  assert_true(codes.contains("pe.no-safeseh"))
  assert_true(codes.contains("pe.certificate-table"))
  assert_true(codes.contains("pe.overlay"))
  assert_true(!codes.contains("pe.no-aslr"))
  assert_true(!codes.contains("pe.no-nx"))
  assert_true(!codes.contains("pe.unsigned"))
}

///|
test "security matrix toggles ASLR and NX independently" {
  let no_aslr = build_pe32_array()
  put_u16(no_aslr, 0x98 + 70, 0x0100)
  assert_diagnostic(no_aslr, "pe.no-aslr")
  assert_no_diagnostic(no_aslr, "pe.no-nx")

  let no_nx = build_pe32_array()
  put_u16(no_nx, 0x98 + 70, 0x0040)
  assert_diagnostic(no_nx, "pe.no-nx")
  assert_no_diagnostic(no_nx, "pe.no-aslr")
}

///|
test "security matrix requires complete CFG metadata" {
  let enabled = build_pe32_array()
  put_u16(enabled, 0x98 + 70, 0x4140)
  assert_no_diagnostic(enabled, "pe.no-cfg")
  assert_no_diagnostic(enabled, "pe.cfg-metadata-missing")

  let no_table = build_pe32_array()
  put_u16(no_table, 0x98 + 70, 0x4140)
  put_u32(no_table, 0x850, 0)
  assert_no_diagnostic(no_table, "pe.no-cfg")
  assert_diagnostic(no_table, "pe.cfg-metadata-missing")

  let no_entries = build_pe32_array()
  put_u16(no_entries, 0x98 + 70, 0x4140)
  put_u32(no_entries, 0x854, 0)
  assert_diagnostic(no_entries, "pe.cfg-metadata-missing")
}

///|
test "security matrix reports high entropy VA only for 64-bit images" {
  assert_diagnostic(build_pe32_plus_array(), "pe.no-high-entropy-va")
  assert_no_diagnostic(build_pe32_array(), "pe.no-high-entropy-va")

  let enabled = build_pe32_plus_array()
  put_u16(enabled, 0x98 + 70, 0x4160)
  assert_no_diagnostic(enabled, "pe.no-high-entropy-va")
}

///|
test "security matrix isolates RWX and entry-point layout checks" {
  let rwx = build_pe32_array()
  put_u32(rwx, 0x98 + 0xe0 + 36, 0xe0000020)
  assert_diagnostic(rwx, "pe.rwx-section")

  let entry = build_pe32_array()
  put_u32(entry, 0x98 + 16, 0x3000)
  assert_diagnostic(entry, "pe.entrypoint-not-executable")

  let no_entry = build_pe32_array()
  put_u32(no_entry, 0x98 + 16, 0)
  assert_no_diagnostic(no_entry, "pe.entrypoint-not-executable")
}

///|
test "security matrix requires relocations when ASLR is enabled" {
  let no_relocations = build_pe32_array()
  put_u32(no_relocations, 0x98 + 96 + 40, 0)
  put_u32(no_relocations, 0x98 + 96 + 44, 0)
  assert_diagnostic(no_relocations, "pe.aslr-without-relocations")

  let no_aslr = build_pe32_array()
  put_u16(no_aslr, 0x98 + 70, 0x0100)
  put_u32(no_aslr, 0x98 + 96 + 40, 0)
  put_u32(no_aslr, 0x98 + 96 + 44, 0)
  assert_no_diagnostic(no_aslr, "pe.aslr-without-relocations")
}

///|
test "security matrix accepts either SafeSEH metadata or NO_SEH" {
  let metadata = build_pe32_array()
  put_u32(metadata, 0x840, 0x401000)
  put_u32(metadata, 0x844, 1)
  assert_no_diagnostic(metadata, "pe.no-safeseh")

  let disabled = build_pe32_array()
  put_u16(disabled, 0x98 + 70, 0x0540)
  assert_no_diagnostic(disabled, "pe.no-safeseh")

  let missing = build_pe32_array()
  put_u32(missing, 0x840, 0)
  put_u32(missing, 0x844, 0)
  assert_diagnostic(missing, "pe.no-safeseh")
}

///|
test "security matrix requires a security cookie in load config" {
  let missing = build_pe32_array()
  put_u32(missing, 0x83c, 0)
  assert_diagnostic(missing, "pe.no-security-cookie")
  assert_no_diagnostic(build_pe32_array(), "pe.no-security-cookie")
}

///|
test "security matrix distinguishes signed and unsigned images" {
  assert_diagnostic(build_pe32_array(), "pe.certificate-table")
  assert_no_diagnostic(build_pe32_array(), "pe.unsigned")

  let unsigned = build_pe32_array()
  put_u32(unsigned, 0x98 + 96 + 32, 0)
  put_u32(unsigned, 0x98 + 96 + 36, 0)
  assert_diagnostic(unsigned, "pe.unsigned")
  assert_no_diagnostic(unsigned, "pe.certificate-table")
}

///|
test "security matrix reports only an actual overlay" {
  assert_diagnostic(build_pe32_array(), "pe.overlay")
  let without_overlay = build_pe32_array()
  without_overlay.resize(0x1000, b'\x00')
  assert_no_diagnostic(without_overlay, "pe.overlay")
}

///|
test "security matrix reports checksum mismatches only when stored" {
  assert_no_diagnostic(build_pe32_array(), "pe.checksum-mismatch")
  let mismatch = build_pe32_array()
  put_u32(mismatch, 0x98 + 64, 1)
  assert_diagnostic(mismatch, "pe.checksum-mismatch")
}

///|
test "security matrix reports high entropy sections above the threshold" {
  let buffer = build_pe32_array()
  put_u32(buffer, 0x98 + 96 + 80, 0)
  put_u32(buffer, 0x98 + 96 + 84, 0)
  for index in 0..<0xe00 {
    buffer[0x200 + index] = (index % 256).to_byte()
  }
  assert_diagnostic(buffer, "pe.high-entropy-section")
}
