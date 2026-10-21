// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "404-32/moon-pe-inspect"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/404-32/byc001"

license = "Apache-2.0"

keywords = [ "pe", "coff", "binary-analysis", "security", "windows" ]

preferred_target = "wasm"

description = "Safe PE/COFF inspection, import/export extraction, and security metadata auditing for MoonBit."

import {
  "moonbitlang/async@0.22.5",
}
