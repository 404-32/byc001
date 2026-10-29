#!/usr/bin/env python3
"""Verify that the active MoonBit compiler meets the project minimum."""

from __future__ import annotations

import re
import subprocess
import sys


MINIMUM_VERSION = (0, 10, 16)


def main() -> int:
    result = subprocess.run(
        ["moonc", "-v"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = f"{result.stdout}\n{result.stderr}"
    match = re.search(r"\bv(\d+)\.(\d+)\.(\d+)", output)
    if result.returncode != 0 or match is None:
        print("toolchain gate: unable to determine moonc version", file=sys.stderr)
        return 1

    version = tuple(int(part) for part in match.groups())
    minimum = ".".join(str(part) for part in MINIMUM_VERSION)
    print(f"toolchain gate: moonc {match.group(0)}, minimum v{minimum}")
    if version < MINIMUM_VERSION:
        print(
            f"toolchain gate failed: moonc must be at least v{minimum}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
