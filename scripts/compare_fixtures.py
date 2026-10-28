"""Run the baseline checks against both fixture apps and print pass/fail.

The checks are the same functions used by tests/test_baseline.py. The vulnerable
app is expected to fail only the non-owner checks.

    python scripts/compare_fixtures.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_baseline import CHECKS, BaselineCheck, api_client

TARGETS = ("vulnerable", "secure")


async def _run_check(target: str, check: BaselineCheck) -> str:
    try:
        async with api_client(target) as client:
            await check.run(client)
    except AssertionError:
        return "FAIL"
    return "PASS"


def _print_table(results: dict[tuple[str, str], str]) -> None:
    header = ("check",) + TARGETS
    rows = [
        (check.name,) + tuple(results[(check.name, target)] for target in TARGETS)
        for check in CHECKS
    ]
    widths = [
        max(len(header[index]), *(len(row[index]) for row in rows))
        for index in range(len(header))
    ]

    def format_row(row: tuple[str, ...]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip()

    print(format_row(header))
    print(format_row(tuple("-" * width for width in widths)))
    for row in rows:
        print(format_row(row))


def _mismatches(results: dict[tuple[str, str], str]) -> list[str]:
    found: list[str] = []
    for check in CHECKS:
        for target in TARGETS:
            actual = results[(check.name, target)]
            expected = "FAIL" if target == "vulnerable" and check.expect_vulnerable_failure else "PASS"
            if actual != expected:
                found.append(f"{target} / {check.name}: {actual}, expected {expected}")
    return found


async def _main() -> int:
    results: dict[tuple[str, str], str] = {}
    for check in CHECKS:
        for target in TARGETS:
            results[(check.name, target)] = await _run_check(target, check)
    _print_table(results)
    mismatches = _mismatches(results)
    if mismatches:
        print()
        print("Unexpected results:")
        for line in mismatches:
            print(f"  {line}")
        return 1
    print()
    print("Vulnerable app failed the non-owner checks. Secure app passed every check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
