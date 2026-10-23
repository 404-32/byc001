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
    buf = bytearray(0x1000)
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
    put(buf, optional + 56, "<II", 0x3000, 0x200)
    put(buf, optional + 68, "<HH", 3, 0x0140)
    put(buf, optional + 92, "<I", 16)

    directories = optional + 96
    put(buf, directories, "<IIII", 0x1100, 0x100, 0x1080, 40)
    put(buf, directories + 16, "<II", 0x1200, 0x100)
    put(buf, directories + 24, "<II", 0x1700, 12)
    put(buf, directories + 40, "<II", 0x1300, 12)
    put(buf, directories + 48, "<II", 0x1400, 28)
    put(buf, directories + 72, "<II", 0x1500, 24)
    put(buf, directories + 80, "<II", 0x1600, 92)
    put(buf, directories + 104, "<II", 0x1800, 64)

    section = optional + 0xE0
    put_ascii(buf, section, ".text")
    put(buf, section + 8, "<IIII", 0xC00, 0x1000, 0xE00, 0x200)
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

    # Resource directory: RCDATA/101/1033.
    put(buf, 0x40C, "<HH", 0, 1)
    put(buf, 0x410, "<II", 10, 0x80000018)
    put(buf, 0x424, "<HH", 0, 1)
    put(buf, 0x428, "<II", 101, 0x80000030)
    put(buf, 0x43C, "<HH", 0, 1)
    put(buf, 0x440, "<II", 1033, 0x50)
    put(buf, 0x450, "<III", 0x12A0, 4, 0)
    put_ascii(buf, 0x4A0, "DATA")

    # Base relocations.
    put(buf, 0x500, "<IIH", 0x1000, 12, 0x3004)

    # CodeView debug entry and RSDS payload.
    put(buf, 0x60C, "<I", 2)
    put(buf, 0x610, "<II", 32, 0x1460)
    put(buf, 0x618, "<I", 0x660)
    put_ascii(buf, 0x660, "RSDS")
    buf[0x664 : 0x674] = bytes(range(1, 17))
    put(buf, 0x674, "<I", 7)
    put_ascii(buf, 0x678, "app.pdb")

    # TLS directory and one callback.
    put(buf, 0x700, "<IIIII", 0x401040, 0x401044, 0x402000, 0x401760, 4)
    put(buf, 0x714, "<I", 0)
    put(buf, 0x960, "<II", 0x401000, 0)

    # PE32 load-config directory.
    put(buf, 0x800, "<IIII", 92, 123, 0, 0)
    put(buf, 0x83C, "<I", 0x401760)
    put(buf, 0x848, "<I", 0x401760)
    put(buf, 0x850, "<II", 0x401000, 2)
    put(buf, 0x858, "<I", 0x100)

    # x64-style exception entry.
    put(buf, 0x900, "<III", 0x1000, 0x1010, 0x1750)

    # Delay-import descriptor, names, and thunks.
    put(buf, 0xA00, "<IIIII", 1, 0x1A70, 0, 0x1A88, 0x1A90)
    put(buf, 0xA1C, "<I", 456)
    put_ascii(buf, 0xC70, "USER32.dll")
    put(buf, 0xC88, "<II", 0x1AA0, 0)
    put(buf, 0xC90, "<II", 0x1AA0, 0)
    put(buf, 0xCA0, "<H", 0)
    put_ascii(buf, 0xCA2, "MessageBoxW")
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
