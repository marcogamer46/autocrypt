#!/usr/bin/env python3
"""Regression for the mixed-alphanumeric Caesar solver (base36-caesar).

Training source: CSAW Red 2020 "Caesar Salad Edition" (raw ciphertext).
Cipher: rotate over alphabet "0123456789abcdefghijklmnopqrstuvwxyz" by +17
(e.g. `y4tz{` -> `flag{`). The solver must recover the plaintext, including
the flag, from raw ciphertext.
"""
import sys
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CHALLENGE = ROOT / "real_challenges" / "online_train" / "Caesar_Salad_Edition" / "challenge.txt"
EXPECTED_FLAG = "flag{0lly_1s_th3_w3st3rosi_brutu5}"


def solver_direct():
    """Unit-style: call the solver directly and require the exact flag."""
    import autocrypt.solvers as solvers
    from autocrypt.core import Context
    from autocrypt.scoring import assess
    import time
    data = CHALLENGE.read_bytes()
    ctx = Context(deadline=time.monotonic() + 20, flag_regex=None,
                  flag_regex_explicit=False, known_plaintext="",
                  wordlist=[], rsa_params={}, assess=assess, jobs=1)
    texts = []
    for out, m, p, s in solvers.solve_base36_caesar(data, ctx):
        texts.append(out)
    if not texts:
        return False, "solver returned no candidates"
    for t in texts:
        if EXPECTED_FLAG.lower() in t.lower():
            return True, f"solver recovered ({len(texts)} candidates)"
    return False, "solver did not recover expected flag"


def pipeline_engages():
    """The full pipeline should at least engage the base36-caesar chain."""
    args = [sys.executable, "-m", "autocrypt.cli", str(CHALLENGE), "--timeout", "30",
            "--json", "--top", "8"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120,
                       cwd=str(ROOT))
    if not r.stdout:
        return False, "no json output"
    import json
    try:
        out = json.loads(r.stdout)
    except Exception:
        return False, "bad json"
    chains = [res.get("chain", "") for res in out.get("results", [])]
    if any("base36-caesar" in c for c in chains):
        return True, f"base36-caesar in chains: {chains[:3]}"
    return False, f"base36-caesar not engaged: {chains[:4]}"


def main():
    ok1, note1 = solver_direct()
    ok2, note2 = pipeline_engages()
    print(f"base36-caesar direct : {'PASS' if ok1 else 'FAIL'} ({note1})")
    print(f"base36-caesar pipeline: {'PASS' if ok2 else 'FAIL'} ({note2})")
    return 0 if ok1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
