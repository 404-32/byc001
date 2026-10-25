// SPDX-License-Identifier: Apache-2.0

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

///|
pub(all) struct ResourceEntry {
  path : String
  type_id : Int32?
  name_id : Int32?
  language_id : Int32?
  data_rva : UInt64
  file_offset : Int32?
  size : Int32
  code_page : Int32
}

///|
pub(all) struct RelocationBlock {
  page_rva : UInt64
  entries : Array[RelocationEntry]
}

///|
pub(all) struct RelocationEntry {
  relocation_type : Int32
  offset : Int32
  target_rva : UInt64
}

///|
pub(all) struct DelayImportLibrary {
  name : String
  attributes : Int32
  timestamp : Int32
  symbols : Array[ImportSymbol]
}

///|
pub(all) struct TlsInfo {
  raw_data_start : UInt64
  raw_data_end : UInt64
  index_address : UInt64
  callbacks_address : UInt64
  size_of_zero_fill : Int32
  characteristics : Int32
  callbacks : Array[UInt64]
}

///|
pub(all) struct DebugEntry {
  debug_type : Int32
  type_name : String
  timestamp : Int32
  size_of_data : Int32
  address_of_raw_data : UInt64
  pointer_to_raw_data : Int32
  pdb_path : String?
  pdb_age : Int32?
  pdb_guid : String?
}

///|
pub(all) struct LoadConfigInfo {
  structure_size : Int32
  timestamp : Int32
  global_flags_clear : Int32?
  global_flags_set : Int32?
  security_cookie : UInt64?
  se_handler_table : UInt64?
  se_handler_count : Int32?
  guard_cf_check_pointer : UInt64?
  guard_cf_dispatch_pointer : UInt64?
  guard_cf_function_table : UInt64?
  guard_cf_function_count : Int32?
  guard_flags : Int32?
}

///|
pub(all) struct ExceptionEntry {
  begin_rva : UInt64
  end_rva : UInt64
  unwind_info_rva : UInt64
}

///|
pub(all) struct DiffItem {
  field : String
  before : String
  after : String
}

///|
pub(all) struct BoundForwarder {
  name : String
  timestamp : Int32
}

///|
pub(all) struct BoundImport {
  name : String
  timestamp : Int32
  forwarders : Array[BoundForwarder]
}

///|
pub(all) struct ClrHeaderInfo {
  header_size : Int32
  major_runtime_version : Int32
  minor_runtime_version : Int32
  metadata_rva : UInt64
  metadata_size : Int32
  flags : Int32
  entry_point_token : Int32
  resources_rva : UInt64
  resources_size : Int32
  strong_name_rva : UInt64
  strong_name_size : Int32
}

///|
pub(all) struct CertificateRecord {
  length : Int32
  revision : Int32
  certificate_type : Int32
}

///|
pub(all) struct OverlayInfo {
  offset : Int32
  size : Int32
}

///|
pub(all) struct ChecksumInfo {
  stored : Int32
  computed : Int32
  present : Bool
  valid : Bool
}

///|
pub(all) struct RichEntry {
  product_id : Int32
  build_id : Int32
  use_count : Int32
}

///|
pub(all) struct RichHeaderInfo {
  xor_key : UInt64
  entries : Array[RichEntry]
}

///|
pub(all) struct SectionEntropy {
  section_name : String
  entropy : Double
  raw_size : Int32
}

///|
pub fn PEImage::va_to_rva(self : Self, va : UInt64) -> UInt64? {
  if va < self.image_base {
    return None
  }
  let rva = va - self.image_base
  if rva < self.size_of_image.to_uint64() {
    Some(rva)
  } else {
    None
  }
}
