// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::security_diagnostics(self : Self) -> Array[Diagnostic] {
  let diagnostics = []
  let load_config = self.load_config() catch { PeError(_, _) => None }
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
  } else {
    let guard_ready = match load_config {
      Some(config) =>
        config.guard_cf_function_count.unwrap_or(0) > 0 &&
        config.guard_cf_function_table.unwrap_or(0UL) != 0UL
      None => false
    }
    if !guard_ready {
      diagnostics.push({
        severity: Warning,
        code: "pe.cfg-metadata-missing",
        message: "GUARD_CF is set but load-config has no guard function table",
      })
    }
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
  if has_bit(self.dll_characteristics, 0x0040) {
    let has_relocations = match self.directory(5) {
      Some(directory) => directory.virtual_address != 0UL && directory.size > 0
      None => false
    }
    if !has_relocations {
      diagnostics.push({
        severity: Warning,
        code: "pe.aslr-without-relocations",
        message: "DYNAMIC_BASE is set but no base-relocation directory is present",
      })
    }
  }
  if !self.is_64_bit() && !has_bit(self.dll_characteristics, 0x0400) {
    let safe_seh = match load_config {
      Some(config) =>
        config.se_handler_count.unwrap_or(0) > 0 &&
        config.se_handler_table.unwrap_or(0UL) != 0UL
      None => false
    }
    if !safe_seh {
      diagnostics.push({
        severity: Warning,
        code: "pe.no-safeseh",
        message: "32-bit image has neither NO_SEH nor SafeSEH metadata",
      })
    }
  }
  match load_config {
    Some(config) if config.security_cookie.unwrap_or(0UL) == 0UL =>
      diagnostics.push({
        severity: Warning,
        code: "pe.no-security-cookie",
        message: "load-config does not declare a /GS security cookie",
      })
    _ => ()
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
  match self.overlay() {
    Some(overlay) =>
      diagnostics.push({
        severity: if overlay.size > 1048576 {
          Warning
        } else {
          Info
        },
        code: "pe.overlay",
        message: "file contains \{overlay.size} bytes after the mapped PE sections",
      })
    None => ()
  }
  let checksum = self.checksum_info()
  if checksum.present && !checksum.valid {
    diagnostics.push({
      severity: Warning,
      code: "pe.checksum-mismatch",
      message: "stored PE checksum does not match the file contents",
    })
  }
  diagnostics
}

///|
fn has_bit(value : Int32, mask : Int32) -> Bool {
  (value & mask) != 0
}
