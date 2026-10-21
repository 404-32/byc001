///|
test "public API exposes architecture metadata" {
  assert_eq(@moon-pe-inspect.architecture_name(0x8664), "x86-64")
  assert_eq(@moon-pe-inspect.subsystem_name(3), "windows-console")
}
