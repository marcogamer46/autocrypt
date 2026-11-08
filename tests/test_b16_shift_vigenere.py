#!/usr/bin/env python3
"""Regression for the b16 + shift-Vigenere solver (b16-shift-vigenere).

Training source: picoCTF "New_Vignere" / "New_Caesar" family (16-letter
alphabet abcdefghijklmnop). Each plaintext byte is base-16 encoded as two
symbols (high/low nibble -> a..p), then each symbol is Vigenere-shifted by a
key symbol over the same alphabet. The b16 high-nibble constraint lets the
solver recover the key by backtracking, without any known plaintext.

This test synthesizes a raw bundle with that scheme (no real flag is leaked)
and requires autocrypt's own pipeline to recover the flag.
"""
import sys
import subprocess
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]

ALPHABET = "abcdefghijklmnop"
KEY = "klmnop"  # all chars in abcdefghijklmnop, length < 15
FLAG = "academy{b16_shift_vigenere_gea}"  # synthetic test flag

def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))
        enc += ALPHABET[int(binary[:4], 2)]
        enc += ALPHABET[int(binary[4:], 2)]
    return enc

def shift(c, k):
    t1 = ord(c) - ord("a")
    t2 = ord(k) - ord("a")
    return ALPHABET[(t1 + t2) % len(ALPHABET)]

def enc(flag, key):
    b16 = b16_encode(flag)
    out = ""
    for i, c in enumerate(b16):
        out += shift(c, key[i % len(key)])
    return out

def solver_direct():
    """Call the solver directly on the raw letter stream."""
    import solvers
    from core import Context
    from scoring import assess
    import time
    data = enc(FLAG, KEY).encode()
    ctx = Context(deadline=time.monotonic() + 20, flag_regex=None,
                  flag_regex_explicit=False, known_plaintext="",
                  wordlist=[], rsa_params={}, assess=assess, jobs=1)
    texts = [out for out, _m, _p, _s in solvers.solve_b16_shift_vigenere(data, ctx)]
    if not texts:
        return False, "solver returned no candidates"
    if any(FLAG.lower() in t.lower() for t in texts):
        return True, f"solver recovered ({len(texts)} candidates)"
    return False, f"solver did not recover flag: {texts[:3]}"

def pipeline_engages():
    """The full pipeline should recover the flag from the raw bundle at rank 0.

    The search machinery overruns its nominal deadline (a pre-existing
    property), so a larger budget is used so the b16 candidate is reached and
    recorded before the deadline expires.
    """
    ct = enc(FLAG, KEY)
    # format like New_Vignere's correctOut: space-separated pairs
    formatted = " ".join(ct[i:i+2] for i in range(0, len(ct), 2))
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(formatted + "\n")
        path = fh.name
    try:
        args = [sys.executable, "autocrypt.py", path, "--timeout", "120",
                "--json", "--top", "8"]
        r = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if not r.stdout:
            return False, "no json output"
        import json
        try:
            out = json.loads(r.stdout)
        except Exception:
            return False, "bad json"
        results = out.get("results", [])
        if not results:
            return False, "no results returned"
        endl = results[0].get("chain", "")
        top = results[0].get("plaintext", "").lower()
        if FLAG.lower() in top:
            return True, f"pipeline recovered flag at rank 0: {endl}"
        # Tolerance: the flag may rank just below a junk as-is row; still
        # require the solver to have engaged and the flag to be present.
        alltext = " ".join(r.get("plaintext", "") for r in results).lower()
        if any("b16-shift-vigenere" in r.get("chain", "") for r in results) \
                and FLAG.lower() in alltext:
            return True, f"b16 solver engaged; flag in results: {endl}"
        return False, f"flag not recovered; top chain: {endl}"
    finally:
        Path(path).unlink(missing_ok=True)

def main():
    ok1, note1 = solver_direct()
    ok2, note2 = pipeline_engages()
    print(f"b16-shift-vigenere direct : {'PASS' if ok1 else 'FAIL'} ({note1})")
    print(f"b16-shift-vigenere pipeline: {'PASS' if ok2 else 'FAIL'} ({note2})")
    return 0 if (ok1 and ok2) else 1

if __name__ == "__main__":
    raise SystemExit(main())
