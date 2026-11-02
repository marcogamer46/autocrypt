#!/usr/bin/env python3
"""E3 parse/run diagnosis: for each failing pair output.txt, print blob head,
fingerprint classes, and which solvers ran (solver_times non-zero) with
seconds. Evidence for the P/S/A grouping."""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import Context, search, fingerprint
import solvers  # noqa: F401

PAIRS = ["c01", "c02", "c03", "c04", "c07", "c08", "c09", "c10",
         "c11", "c12", "c13", "c14", "c15"]


def main():
    for name in PAIRS:
        p = Path("fixtures/e3") / f"{name}_output.txt"
        data = p.read_bytes()
        fp = fingerprint(data)
        ctx = Context(deadline=time.monotonic() + 25,
                      flag_regex=re.compile(r"\w{1,40}\{.*?\}", re.DOTALL),
                      flag_regex_explicit=False, known_plaintext="",
                      wordlist=[], rsa_params={},
                      assess=__import__("scoring").assess, jobs=1)
        res = search(data, ctx, top=3)
        times = {k: round(v, 2) for k, v in sorted(
            ctx.solver_times.items(), key=lambda kv: -kv[1])[:5] if v > 0}
        print(f"== {name} status={res.status}")
        print(f"   fp charset={fp['charset']} classes={fp['classes']} len={len(data)}")
        try:
            head = data.decode('ascii', 'replace')[:80].replace('\n', '|')
        except Exception:
            head = ""
        print(f"   blob_head: {head!r}")
        print(f"   solvers_run: {times}")


if __name__ == "__main__":
    main()
