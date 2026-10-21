///|
pub(all) enum PEFormat {
  PE32
  PE32Plus
}

///|
pub(all) enum Severity {
  Info
  Warning
  Critical
}

///|
pub(all) struct Section {
  name : String
  virtual_size : Int32
  virtual_address : UInt64
  raw_size : Int32
  raw_offset : Int32
  characteristics : UInt64
}

///|
pub(all) struct DataDirectory {
  index : Int32
  name : String
  virtual_address : UInt64
  size : Int32
}

///|
pub(all) struct ImportSymbol {
  name : String?
  ordinal : Int32?
  hint : Int32?
}

///|
pub(all) struct ImportLibrary {
  name : String
  symbols : Array[ImportSymbol]
}

///|
pub(all) struct ExportSymbol {
  name : String
  ordinal : Int32
  rva : UInt64
  forwarder : String?
}

///|
pub(all) struct Diagnostic {
  severity : Severity
  code : String
  message : String
}

///|
pub(all) suberror PeError {
  PeError(Int32, String)
}

///|
pub(all) struct PEImage {
  data : Bytes
  pe_offset : Int32
  format : PEFormat
  machine : Int32
  number_of_sections : Int32
  timestamp : UInt64
  symbol_table_pointer : UInt64
  number_of_symbols : UInt64
  size_of_optional_header : Int32
  characteristics : Int32
  entry_point : UInt64
  image_base : UInt64
  section_alignment : Int32
  file_alignment : Int32
  size_of_image : Int32
  size_of_headers : Int32
  checksum : UInt64
  subsystem : Int32
  dll_characteristics : Int32
  sections : Array[Section]
  directories : Array[DataDirectory]
}

///|
pub fn PEImage::is_64_bit(self : Self) -> Bool {
  self.format is PE32Plus
}

///|
pub fn PEImage::section_by_name(self : Self, name : String) -> Section? {
  let mut found = None
  for section in self.sections {
    if section.name == name {
      found = Some(section)
    }
  }
  found
}

///|
pub fn PEImage::directory(self : Self, index : Int32) -> DataDirectory? {
  for directory in self.directories {
    if directory.index == index {
      return Some(directory)
    }
  }
  None
}

///|
pub fn architecture_name(machine : Int32) -> String {
  match machine {
    0x014c => "x86"
    0x8664 => "x86-64"
    0x01c0 => "ARM"
    0xaa64 => "ARM64"
    0x0200 => "IA64"
    _ => "unknown"
  }
}

///|
pub fn subsystem_name(subsystem : Int32) -> String {
  match subsystem {
    1 => "native"
    2 => "windows-gui"
    3 => "windows-console"
    7 => "posix-console"
    9 => "windows-ce"
    10 => "efi-application"
    11 => "efi-boot-service"
    12 => "efi-runtime"
    14 => "xbox"
    16 => "windows-boot-application"
    _ => "unknown"
  }
}
