#!/usr/bin/env python3
"""Generate deterministic PE32 and PE32+ fixtures used by local and CI demos."""

from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def put(buf: bytearray, offset: int, fmt: str, *values: int) -> None:
    struct.pack_into(fmt, buf, offset, *values)


def put_ascii(buf: bytearray, offset: int, value: str) -> None:
    data = value.encode("ascii")
    buf[offset : offset + len(data)] = data


def pe32_fixture() -> bytes:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    put(buf, 0x3C, "<I", 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    put(buf, 0x84, "<HHIIIHH", 0x014C, 1, 0x5F3759DF, 0, 0, 0xE0, 0x0102)

    optional = 0x98
    put(buf, optional, "<H", 0x10B)
    put(buf, optional + 16, "<I", 0x1000)
    put(buf, optional + 20, "<I", 0x1000)
    put(buf, optional + 28, "<I", 0x400000)
    put(buf, optional + 32, "<II", 0x1000, 0x200)
    put(buf, optional + 56, "<II", 0x2000, 0x200)
    put(buf, optional + 68, "<HH", 3, 0x0140)
    put(buf, optional + 92, "<I", 16)

    directories = optional + 96
    put(buf, directories, "<IIII", 0x1100, 0x100, 0x1080, 40)

    section = optional + 0xE0
    put_ascii(buf, section, ".text")
    put(buf, section + 8, "<IIII", 0x200, 0x1000, 0x200, 0x200)
    put(buf, section + 36, "<I", 0x60000020)

    # Export directory at RVA 0x1100 / file offset 0x300.
    put(buf, 0x30C, "<I", 0x1140)
    put(buf, 0x310, "<I", 1)
    put(buf, 0x314, "<I", 1)
    put(buf, 0x318, "<I", 1)
    put(buf, 0x31C, "<I", 0x1160)
    put(buf, 0x320, "<I", 0x1164)
    put(buf, 0x324, "<I", 0x1168)
    put_ascii(buf, 0x340, "sample.dll")
    put(buf, 0x360, "<I", 0x1000)
    put(buf, 0x364, "<I", 0x1170)
    put(buf, 0x368, "<H", 0)
    put_ascii(buf, 0x370, "exported")

    # Import directory at RVA 0x1080 / file offset 0x280.
    put(buf, 0x280, "<IIIII", 0x1180, 0, 0, 0x11A0, 0x1188)
    put(buf, 0x380, "<II", 0x11B0, 0)
    put(buf, 0x388, "<II", 0x11B0, 0)
    put_ascii(buf, 0x3A0, "KERNEL32.dll")
    put(buf, 0x3B0, "<H", 0)
    put_ascii(buf, 0x3B2, "ExitProcess")
    return bytes(buf)


def pe32_plus_fixture() -> bytes:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    put(buf, 0x3C, "<I", 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    put(buf, 0x84, "<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)

    optional = 0x98
    put(buf, optional, "<H", 0x20B)
    put(buf, optional + 16, "<I", 0x1000)
    put(buf, optional + 20, "<I", 0x1000)
    put(buf, optional + 24, "<Q", 0x140000000)
    put(buf, optional + 32, "<II", 0x1000, 0x200)
    put(buf, optional + 56, "<II", 0x2000, 0x200)
    put(buf, optional + 68, "<HH", 3, 0x4140)
    put(buf, optional + 108, "<I", 0)

    section = optional + 0xF0
    put_ascii(buf, section, ".text")
    put(buf, section + 8, "<IIII", 0x200, 0x1000, 0x200, 0x200)
    put(buf, section + 36, "<I", 0x60000020)
    return bytes(buf)


def main() -> None:
    EXAMPLES.mkdir(exist_ok=True)
    (EXAMPLES / "minimal-pe32.exe").write_bytes(pe32_fixture())
    (EXAMPLES / "minimal-pe32plus.exe").write_bytes(pe32_plus_fixture())


if __name__ == "__main__":
    main()
