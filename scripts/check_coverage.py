#!/usr/bin/env python3
"""Enforce minimum MoonBit line coverage for the parser package."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MINIMUM_TOTAL = 0.85
MINIMUM_BY_FILE = {
    "parser.mbt": 0.98,
    "security.mbt": 0.95,
}


def percentage(covered: int, total: int) -> float:
    return covered / total if total else 0.0


def main() -> int:
    report_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/coverage.txt")
    text = report_path.read_text(encoding="utf-8", errors="replace")

    total_match = re.search(r"Total:\s*(\d+)/(\d+)", text)
    if total_match is None:
        print("coverage gate: missing total line", file=sys.stderr)
        return 1

    covered = int(total_match.group(1))
    total = int(total_match.group(2))
    measured_total = percentage(covered, total)
    failures: list[str] = []
    if measured_total < MINIMUM_TOTAL:
        failures.append(
            f"total {measured_total:.2%} is below {MINIMUM_TOTAL:.0%}"
        )

    measurements = {
        name: percentage(int(file_covered), int(file_total))
        for name, file_covered, file_total in re.findall(
            r"([A-Za-z0-9_.-]+\.mbt):\s*(\d+)/(\d+)", text
        )
    }
    for name, minimum in MINIMUM_BY_FILE.items():
        measured = measurements.get(name)
        if measured is None:
            failures.append(f"{name} is missing from the coverage report")
        elif measured < minimum:
            failures.append(f"{name} {measured:.2%} is below {minimum:.0%}")

    print(f"coverage gate: total {covered}/{total} ({measured_total:.2%})")
    for name in MINIMUM_BY_FILE:
        if name in measurements:
            print(f"coverage gate: {name} {measurements[name]:.2%}")

    if failures:
        for failure in failures:
            print(f"coverage gate failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
