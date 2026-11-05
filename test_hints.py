#!/usr/bin/env python3
"""E3 source-hint emission check.

For each target fixture, `challenge.load` merges the challenge .py with the
output .txt and must emit the expected `name=value` hint marker into the data
text. Verifies the challenge->solver plumbing end-to-end (static only; nothing
is executed). Prints a PASS/FAIL table and exits non-zero on any failure.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
E3 = ROOT / "fixtures" / "e3"

sys.path.insert(0, str(ROOT))
import challenge  # noqa: E402

EXPECTED = [
    ("c02", "shift=7"),
    ("c03", "key_bytes=0x63727970746f"),
    ("c04", "key_bytes=0x6834636b"),
    ("c07", "secret_bytes=0x70723074306e2d736563726574"),
    ("c12", "a=123456789987654321"),
    ("c13", "password_bytes=0x6c65746d65696e"),
    ("c15", "key=0x"),
]


def main():
    failures = 0
    print(f"{'CASE':5} {'RES':5} {'MARKER'}")
    for name, marker in EXPECTED:
        try:
            data, _, _ = challenge.load([str(E3 / f"{name}_challenge.py"),
                                         str(E3 / f"{name}_output.txt")])
            text = data.decode("utf-8", "replace")
        except Exception as exc:  # should not happen; report as failure
            text = ""
            print(f"{name:5} ERROR  {type(exc).__name__}: {exc}")
            failures += 1
            continue
        if marker in text:
            print(f"{name:5} PASS   {marker}")
        else:
            print(f"{name:5} FAIL   missing {marker!r} (data contains: {text.strip()!r})")
            failures += 1
    print(f"\n{len(EXPECTED) - failures}/{len(EXPECTED)} hint markers emitted")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
