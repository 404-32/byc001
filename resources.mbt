///|
pub fn PEImage::resources(self : Self) -> Array[ResourceEntry] raise PeError {
  let directory = match self.directory(2) {
    Some(directory) if directory.virtual_address != 0UL && directory.size > 0 =>
      directory
    _ => return []
  }
  let entries = []
  self.walk_resource_directory(
    directory.virtual_address,
    directory.virtual_address,
    0,
    "",
    entries,
  )
  entries
}

///|
fn PEImage::walk_resource_directory(
  self : Self,
  resource_base : UInt64,
  directory_rva : UInt64,
  depth : Int32,
  parent_path : String,
  output : Array[ResourceEntry],
) -> Unit raise PeError {
  if depth > 4 || output.length() >= 4096 {
    return
  }
  let offset = self.rva_to_offset(directory_rva)
  ensure_range(self.data, offset, 16)
  let named_count = read_u16(self.data, offset + 12)
  let id_count = read_u16(self.data, offset + 14)
  let count = named_count + id_count
  if count > 4096 {
    raise PeError(offset + 12, "resource entry count exceeds the safety limit")
  }
  ensure_range(self.data, offset + 16, count * 8)
  for index in 0..<count {
    let entry_offset = offset + 16 + index * 8
    let name_value = read_u32(self.data, entry_offset)
    let target_value = read_u32(self.data, entry_offset + 4)
    let name = if name_value.land(0x80000000UL) != 0UL {
      let name_rva = resource_base + name_value.land(0x7fffffffUL)
      self.read_resource_string(name_rva)
    } else {
      let id = name_value.to_int()
      if depth == 0 {
        resource_type_name(id)
      } else {
        "#\{id}"
      }
    }
    let path = if parent_path.is_empty() {
      name
    } else {
      "\{parent_path}/\{name}"
    }
    if target_value.land(0x80000000UL) != 0UL {
      let child_rva = resource_base + target_value.land(0x7fffffffUL)
      self.walk_resource_directory(
        resource_base,
        child_rva,
        depth + 1,
        path,
        output,
      )
    } else {
      let data_entry_rva = resource_base + target_value.land(0x7fffffffUL)
      let data_entry_offset = self.rva_to_offset(data_entry_rva)
      let data_rva = read_u32(self.data, data_entry_offset)
      let size = checked_int(
        read_u32(self.data, data_entry_offset + 4),
        data_entry_offset + 4,
        "resource size",
      )
      let code_page = checked_int(
        read_u32(self.data, data_entry_offset + 8),
        data_entry_offset + 8,
        "resource code page",
      )
      let file_offset = Some(self.rva_to_offset(data_rva)) catch {
        PeError(_, _) => None
      }
      output.push({
        path,
        type_id: if depth == 0 {
          Some(name_value.to_int())
        } else {
          None
        },
        name_id: if depth == 1 {
          Some(name_value.to_int())
        } else {
          None
        },
        language_id: if depth == 2 {
          Some(name_value.to_int())
        } else {
          None
        },
        data_rva,
        file_offset,
        size,
        code_page,
      })
    }
  }
}

///|
fn PEImage::read_resource_string(
  self : Self,
  string_rva : UInt64,
) -> String raise PeError {
  let offset = self.rva_to_offset(string_rva)
  ensure_range(self.data, offset, 2)
  let length = read_u16(self.data, offset)
  if length > 2048 {
    raise PeError(offset, "resource string exceeds the safety limit")
  }
  ensure_range(self.data, offset + 2, length * 2)
  let builder = StringBuilder()
  for index in 0..<length {
    let code = read_u16(self.data, offset + 2 + index * 2)
    if code >= 0x20 && code <= 0x7e {
      builder.write_char(code.unsafe_to_char())
    } else {
      builder.write_char('?')
    }
  }
  builder.to_string()
}

///|
fn resource_type_name(id : Int32) -> String {
  match id {
    1 => "cursor"
    2 => "bitmap"
    3 => "icon"
    4 => "menu"
    5 => "dialog"
    6 => "string-table"
    9 => "accelerator"
    10 => "rcdata"
    11 => "message-table"
    12 => "group-cursor"
    14 => "group-icon"
    16 => "version"
    17 => "dlginclude"
    19 => "plugplay"
    20 => "vxd"
    21 => "anicursor"
    22 => "aniicon"
    23 => "html"
    24 => "manifest"
    _ => "#\{id}"
  }
}
