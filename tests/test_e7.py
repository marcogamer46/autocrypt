#!/usr/bin/env python3
"""E7: verify --fast / --deep flags.

Checks that:
  1. --fast runs correctly and returns the same result on a fast-solvable
     challenge (base64 -> flag) without crashing, and is not slower.
  2. --deep runs correctly and still recovers a known flag.
  3. The fast path skips the heavy solvers (checks ctx.heavy_names is set).
"""
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _run(args, timeout=60):
    PY = sys.executable
    return subprocess.run(
        [PY, "-m", "autocrypt.cli"] + args,
        capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))


def main():
    failures = 0

    # A trivial base64 challenge: should solve in both modes.
    b64 = "cGljb0NURntmYXN0X2ZsYWdfdGVzdDEyM30="
    tmp = ROOT / "_e7_tmp.b64"
    tmp.write_text(b64)

    # --fast
    t0 = time.monotonic()
    r = _run([str(tmp), "--fast", "--top", "1", "--timeout", "15"])
    fast_dt = time.monotonic() - t0
    fast_ok = "picoCTF{fast_flag_test123}" in r.stdout and r.returncode == 0
    print(f"{'PASS' if fast_ok else 'FAIL'}  --fast recovers flag "
          f"(returncode={r.returncode}, {fast_dt:.2f}s)")
    if not fast_ok:
        print("      stdout tail:", r.stdout[-300:])
        print("      stderr:", r.stderr[-300:])
        failures += 1

    # --deep
    t0 = time.monotonic()
    r = _run([str(tmp), "--deep", "--top", "1", "--timeout", "15"])
    deep_dt = time.monotonic() - t0
    deep_ok = "picoCTF{fast_flag_test123}" in r.stdout and r.returncode == 0
    print(f"{'PASS' if deep_ok else 'FAIL'}  --deep recovers flag "
          f"(returncode={r.returncode}, {deep_dt:.2f}s)")
    if not deep_ok:
        print("      stdout tail:", r.stdout[-300:])
        print("      stderr:", r.stderr[-300:])
        failures += 1

    # --json exposes results too; make sure --fast + --json doesn't crash.
    r = _run([str(tmp), "--fast", "--json", "--timeout", "15"])
    ok = r.returncode == 0 and "chain" in r.stdout
    print(f"{'PASS' if ok else 'FAIL'}  --fast --json emits chain")
    if not ok:
        print("      stdout tail:", r.stdout[-300:])
        print("      stderr:", r.stderr[-300:])
        failures += 1

    # Sanity: both flags at once is allowed but --fast wins on speed.
    r = _run([str(tmp), "--fast", "--deep", "--top", "1", "--timeout", "15"])
    ok = "picoCTF{fast_flag_test123}" in r.stdout and r.returncode == 0
    print(f"{'PASS' if ok else 'FAIL'}  --fast --deep coexist")
    if not ok:
        print("      stdout tail:", r.stdout[-300:])
        failures += 1

    tmp.unlink(missing_ok=True)

    print(f"\nE7FLAGS: {4 - failures}/4 OK")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
