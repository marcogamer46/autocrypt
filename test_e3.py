#!/usr/bin/env python3
"""E3 strict harness (one run). PASS only when the TOP row is NOT an as-is /
source echo and its plaintext contains the exact flag. Prints rank, chain,
time-to-first-exact, total wall, expected vs top. Cases over 35s are marked
as budget violations."""
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
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
    args = ["python3", "autocrypt.py"] + [str(p) for p in paths] + \
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
        # ciphertext. Fall back to output alone if the merged run is thin.
        out, wall, fe = run(py, out_txt)
        if len(out) < 3:
            out2, wall2, fe2 = run(out_txt)
            wall += wall2
            fe = fe if fe is not None else fe2
            out = out2 if len(out2) > len(out) else out
        top = out[0] if out else None
        chain = top["chain"] if top else "-"
        top_txt = top["plaintext"] if top else "-"
        echo = chain.lower().startswith("as-is") or "source" in chain.lower()
        contains = flag.lower() in top_txt.lower()
        if top and not echo and contains:
            status, rank = "PASS", 0
        elif top and contains:
            status, rank = "FAIL", "echo"
        else:
            rank = next((k for k, x in enumerate(out)
                         if flag.lower() in x["plaintext"].lower()), None)
            status = "FAIL" if rank is None else f"rank{rank}"
        budget = " BUDGET" if wall > 35 else ""
        print(f"{name:5} {status:6} {str(rank):>4} {str(fe if fe is not None else '-'):>6} {wall:6.1f}  {chain[:46]} | {top_txt[:30]!r} vs {flag!r}{budget}")


if __name__ == "__main__":
    main()
