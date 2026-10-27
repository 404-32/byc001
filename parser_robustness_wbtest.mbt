// SPDX-License-Identifier: Apache-2.0

///|
fn copy_bytes(source : Array[Byte]) -> Array[Byte] {
  let output = Array::make(source.length(), b'\x00')
  for index in 0..<source.length() {
    output[index] = source[index]
  }
  output
}

///|
fn exercise_parsers(data : Bytes) -> Unit {
  let image = PEImage::parse(data) catch { PeError(_, _) => return }
  let _ = image.rva_to_offset(0UL) catch { PeError(_, _) => 0 }
  let _ = image.rva_to_offset(0x1000UL) catch { PeError(_, _) => 0 }
  let _ = image.va_to_rva(image.image_base)
  let _ = image.section_by_name(".text")
  let _ = image.read_c_string(0UL, 64) catch { PeError(_, _) => "" }
  let _ = image.imports() catch { PeError(_, _) => [] }
  let _ = image.exports() catch { PeError(_, _) => [] }
  let _ = image.resources() catch { PeError(_, _) => [] }
  let _ = image.base_relocations() catch { PeError(_, _) => [] }
  let _ = image.delay_imports() catch { PeError(_, _) => [] }
  let _ = image.tls() catch { PeError(_, _) => None }
  let _ = image.debug_entries() catch { PeError(_, _) => [] }
  let _ = image.load_config() catch { PeError(_, _) => None }
  let _ = image.exception_entries() catch { PeError(_, _) => [] }
  let _ = image.bound_imports() catch { PeError(_, _) => [] }
  let _ = image.clr_header() catch { PeError(_, _) => None }
  let _ = image.certificates() catch { PeError(_, _) => [] }
  let _ = image.section_entropies() catch { PeError(_, _) => [] }
  let _ = image.rich_header()
  let _ = image.overlay()
  let _ = image.checksum_info()
  let _ = image.security_diagnostics()
}

///|
test "truncation grid only returns bounded parse results" {
  let pe32 = build_pe32_array()
  let pe32plus = build_pe32_plus_array()
  let mut length = 0
  while length <= pe32.length() {
    let prefix = Array::make(length, b'\x00')
    for index in 0..<length {
      prefix[index] = pe32[index]
    }
    exercise_parsers(Bytes::from_array(prefix))
    length = length + 8
  }
  length = 0
  while length <= pe32plus.length() {
    let prefix = Array::make(length, b'\x00')
    for index in 0..<length {
      prefix[index] = pe32plus[index]
    }
    exercise_parsers(Bytes::from_array(prefix))
    length = length + 8
  }
}

///|
test "structural field grid only returns bounded parse results" {
  let base = build_pe32_array()
  let u16_offsets = [0x84, 0x86, 0x94, 0x96, 0x98 + 68, 0x98 + 70, 0x98 + 92]
  let u16_values = [0, 1, 2, 0x7fff, 0xffff]
  for offset in u16_offsets {
    for value in u16_values {
      let buffer = copy_bytes(base)
      put_u16(buffer, offset, value)
      exercise_parsers(Bytes::from_array(buffer))
    }
  }

  let u32_offsets = [
    0x3c,
    0x88,
    0x98 + 16,
    0x98 + 20,
    0x98 + 28,
    0x98 + 32,
    0x98 + 36,
    0x98 + 56,
    0x98 + 60,
    0x98 + 64,
  ]
  let u32_values = [0, 1, 0x1000, 0x7fffffff, 0x80000000, 0xffffffff]
  for offset in u32_offsets {
    for value in u32_values {
      let buffer = copy_bytes(base)
      put_u32(buffer, offset, value)
      exercise_parsers(Bytes::from_array(buffer))
    }
  }

  let directories = 0x98 + 96
  for index in 0..<16 {
    for part in 0..<2 {
      for value in u32_values {
        let buffer = copy_bytes(base)
        put_u32(buffer, directories + index * 8 + part * 4, value)
        exercise_parsers(Bytes::from_array(buffer))
      }
    }
  }

  let section = 0x98 + 0xe0
  let section_offsets = [section + 8, section + 12, section + 16, section + 20]
  for offset in section_offsets {
    for value in u32_values {
      let buffer = copy_bytes(base)
      put_u32(buffer, offset, value)
      exercise_parsers(Bytes::from_array(buffer))
    }
  }
}

///|
test "deterministic random mutations never panic" {
  let base = build_pe32_array()
  let mut state = 0x13579bdf
  for _ in 0..<2048 {
    let buffer = copy_bytes(base)
    let mutation_count = 1 + state % 6
    for _ in 0..<mutation_count {
      state = (state * 1103515245 + 12345) & 0x7fffffff
      let offset = state % buffer.length()
      state = (state * 1103515245 + 12345) & 0x7fffffff
      let mask = 1 << (state % 8)
      buffer[offset] = (buffer[offset].to_int() ^ mask).to_byte()
    }
    exercise_parsers(Bytes::from_array(buffer))
  }
}
