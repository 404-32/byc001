///|
pub fn PEImage::security_diagnostics(self : Self) -> Array[Diagnostic] {
  let diagnostics = []
  if !has_bit(self.dll_characteristics, 0x0040) {
    diagnostics.push({
      severity: Warning,
      code: "pe.no-aslr",
      message: "DYNAMIC_BASE is not set; the image does not opt into ASLR",
    })
  }
  if !has_bit(self.dll_characteristics, 0x0100) {
    diagnostics.push({
      severity: Warning,
      code: "pe.no-nx",
      message: "NX_COMPAT is not set; executable memory may remain writable",
    })
  }
  if !has_bit(self.dll_characteristics, 0x4000) {
    diagnostics.push({
      severity: Warning,
      code: "pe.no-cfg",
      message: "GUARD_CF is not set; Control Flow Guard metadata is absent",
    })
  }
  if self.is_64_bit() && !has_bit(self.dll_characteristics, 0x0020) {
    diagnostics.push({
      severity: Info,
      code: "pe.no-high-entropy-va",
      message: "HIGH_ENTROPY_VA is not set for this 64-bit image",
    })
  }
  for section in self.sections {
    if has_bit(section.characteristics.to_int(), 0x80000000) &&
      has_bit(section.characteristics.to_int(), 0x20000000) {
      diagnostics.push({
        severity: Critical,
        code: "pe.rwx-section",
        message: "section '\{section.name}' is both writable and executable",
      })
    }
  }
  if self.entry_point != 0UL {
    let mut executable_entry = false
    for section in self.sections {
      let start = section.virtual_address
      let span = if section.virtual_size > section.raw_size {
        section.virtual_size
      } else {
        section.raw_size
      }
      if self.entry_point >= start &&
        self.entry_point < start + span.to_uint64() &&
        has_bit(section.characteristics.to_int(), 0x20000000) {
        executable_entry = true
      }
    }
    if !executable_entry {
      diagnostics.push({
        severity: Warning,
        code: "pe.entrypoint-not-executable",
        message: "AddressOfEntryPoint is not inside an executable section",
      })
    }
  }
  let signed = match self.directory(4) {
    Some(directory) => directory.virtual_address != 0UL && directory.size != 0
    None => false
  }
  if signed {
    diagnostics.push({
      severity: Info,
      code: "pe.certificate-table",
      message: "certificate table is present; this tool does not validate signatures",
    })
  } else {
    diagnostics.push({
      severity: Warning,
      code: "pe.unsigned",
      message: "no Authenticode certificate table is present",
    })
  }
  diagnostics
}

///|
fn has_bit(value : Int32, mask : Int32) -> Bool {
  (value & mask) != 0
}
