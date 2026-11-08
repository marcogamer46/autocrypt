#!/usr/bin/env python3
"""E3 strict harness (one run). PASS only when the TOP row is NOT an as-is /
source echo and its plaintext contains the exact flag. Prints rank, chain,
time-to-first-exact, total wall, expected vs top. Cases over 35s are marked
as budget violations."""
import sys
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E3 = ROOT / "fixtures" / "e3"

CASES = [
    ("c01", "academy{b64_hex_rot13_l4y3r}"),
    ("c02", "academy{caesar_7_hint}"),
    ("c03", "academy{vigenere_key_k3y}"),
    ("c04", "academy{repeat_xor_h4ck_k3y}"),
    ("c05", "academy{rsa_small_e3_unlabeled}"),
    ("c06", "academy{rsa_p_q_printed}"),
    ("c07", "academy{hash_key_xor_sha256}"),
    ("c08", "academy{reverse_b64_caesar_cust0m}"),
    ("c09", "academy{common_modulus_rsa}"),
    ("c10", "academy{hastad_broadcast_e3}"),
    ("c11", "academy{franklin_reiter_related}"),
    ("c12", "academy{dh_shared_secret_xor}"),
    ("c13", "academy{hash_crack_weak_pw}"),
    ("c14", "academy{lfsr_keystream_crib}"),
    ("c15", "academy{single_byte_xor_bin}"),
]


def run(*paths):
    args = [sys.executable, "autocrypt.py"] + [str(p) for p in paths] + \
        ["--timeout", "30", "--json", "--top", "6"]
    t0 = time.time()
    r = subprocess.run(args, capture_output=True, text=True, timeout=90)
    wall = time.time() - t0
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            first_exact = out.get("first_exact")
            out = out.get("results", [])
        else:
            first_exact = None
    except Exception:
        out, first_exact = [], None
    return out, wall, first_exact


def main():
    print(f"{'CASE':5} {'RES':6} {'RANK':4} {'FIRST':>6} {'WALL':>6}  CHAIN | TOP vs EXPECTED")
    for name, flag in CASES:
        py = E3 / f"{name}_challenge.py"
        out_txt = E3 / f"{name}_output.txt"
        # Primary: challenge source + output merged so source hints meet the
        # ciphertext. Fall back to output alone ONLY if the merged run did not
        # surface the flag at all (the merged run is the documented invocation
        # and may legitimately return a thin verified-exact result set).
        def _score(o):
            if not o:
                return "FAIL", None, "-", "-"
            top = o[0]
            chain = top.get("chain", "")
            top_txt = top.get("plaintext", "")
            echo = chain.lower().startswith("as-is") or "source" in chain.lower()
            contains = flag.lower() in top_txt.lower()
            if top and not echo and contains:
                return "PASS", 0, chain, top_txt
            r = next((k for k, x in enumerate(o)
                      if flag.lower() in x["plaintext"].lower()), None)
            if r is None:
                return "FAIL", None, chain, top_txt
            return f"rank{r}", r, chain, top_txt
        out, wall, fe = run(py, out_txt)
        status, rank, chain, top_txt = _score(out)
        if rank is None:
            out2, wall2, fe2 = run(out_txt)
            wall += wall2
            fe = fe if fe is not None else fe2
            if len(out2) > len(out):
                status, rank, chain, top_txt = _score(out2)
        budget = " BUDGET" if wall > 35 else ""
        print(f"{name:5} {status:6} {str(rank):>4} {str(fe if fe is not None else '-'):>6} {wall:6.1f}  {chain[:46]} | {top_txt[:30]!r} vs {flag!r}{budget}")


if __name__ == "__main__":
    main()
