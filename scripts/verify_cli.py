#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Exercise every JSON/SARIF CLI path against deterministic fixtures."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "examples" / "minimal-pe32.exe"
PE_PLUS = ROOT / "examples" / "minimal-pe32plus.exe"
RICH = ROOT / "examples" / "rich-pe32.exe"
COFF = ROOT / "examples" / "minimal-coff.obj"


def run(*args: str, expected_code: int = 0) -> str:
    command = ["moon", "run", "cmd/main", "--", *args]
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != expected_code:
        raise AssertionError(
            f"{' '.join(command)} exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout.strip()


def run_json(*args: str, expected_code: int = 0):
    return json.loads(run(*args, expected_code=expected_code))


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    inspect = run_json("inspect", str(PE), "--json")
    expect(inspect["format"] == "PE32", "inspect format mismatch")
    expect(inspect["sections"] == 1, "inspect section count mismatch")

    sections = run_json("sections", str(PE), "--json")
    expect(len(sections) == 1 and "entropy" in sections[0], "sections output mismatch")

    imports = run_json("imports", str(PE), "--json")
    expect(imports[0]["library"] == "KERNEL32.dll", "imports output mismatch")

    exports = run_json("exports", str(PE), "--json")
    expect(exports[0]["name"] == "exported", "exports output mismatch")

    expect(len(run_json("directories", str(PE), "--json")) >= 8, "directories missing")
    expect(run_json("resources", str(PE), "--json")[0]["path"].startswith("rcdata/"), "resource tree mismatch")
    expect(run_json("relocations", str(PE), "--json")[0]["entries"], "relocation entries missing")
    expect(run_json("delay-imports", str(PE), "--json")[0]["library"] == "USER32.dll", "delay import mismatch")
    expect(run_json("tls", str(PE), "--json")["callbacks"], "TLS callbacks missing")
    expect(run_json("debug", str(PE), "--json")[0]["pdb"] == "app.pdb", "PDB mismatch")
    expect(run_json("load-config", str(PE), "--json")["guardFunctionCount"] == 2, "load config mismatch")
    expect(run_json("exceptions", str(PE), "--json")[0]["beginRva"] == "0x1000", "exception mismatch")
    expect(run_json("bound-imports", str(PE), "--json")[0]["forwarders"], "bound import mismatch")
    expect(run_json("clr", str(PE), "--json")["runtime"] == "2.5", "CLR mismatch")
    expect(run_json("certificates", str(PE), "--json")[0]["type"] == "pkcs-signed-data", "certificate mismatch")
    expect(run_json("overlay", str(PE), "--json")["size"] == 32, "overlay mismatch")
    expect(run_json("checksum", str(PE), "--json")["computed"].startswith("0x"), "checksum mismatch")
    expect(run_json("rich", str(RICH), "--json")["entries"][0]["buildId"] == 0x1234, "Rich header mismatch")
    expect(run_json("coff", str(COFF), "--json")["symbols"][1]["name"] == "long_symbol", "COFF symbols mismatch")
    expect(len(run_json("diff", str(PE), str(PE_PLUS), "--json")) > 0, "diff produced no changes")

    sarif = run_json("security", str(PE), "--sarif")
    expect(sarif["version"] == "2.1.0", "SARIF version mismatch")
    expect(sarif["runs"][0]["results"], "SARIF results missing")

    lint = run_json("lint", str(PE), "--json", expected_code=1)
    expect(lint["passed"] is False and lint["diagnostics"], "lint gate mismatch")
    print("CLI verification passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"CLI verification failed: {error}", file=sys.stderr)
        raise
