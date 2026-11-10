#!/usr/bin/env python3
"""Regression for the labeled LFSR solver (initial state + taps + ciphertext).

Builds a synthetic challenge in the exact pasted format, generated with the
repo's canonical E3 c14 convention (Fibonacci left-shift, low byte of the
register emitted after each advance). The solver must parse the fields and
recover the flag.
"""
import sys
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def make_challenge():
    seed = 0xBEEF
    taps = (15, 13, 12, 10)
    flag = b"academy{lfsr_keystream_crib}"
    mask = 0xFFFF

    def step(state):
        bit = 0
        for t in taps:
            bit ^= (state >> t) & 1
        return ((state << 1) | bit) & mask

    state = seed
    ks = bytearray()
    for _ in range(len(flag)):
        state = step(state)
        ks.append(state & 0xFF)
    ct = bytes(c ^ ks[i] for i, c in enumerate(flag))
    init_list = [int(b) for b in format(seed, "016b")]
    txt = ("LFSR Initial State:\n" + str(init_list) + "\n"
           "LFSR Taps:\n[15, 13, 12, 10]\n"
           "Encrypted Flag:\n" + ct.hex() + "\n")
    return txt, flag


class FakeCtx:
    depth = 0
    rsa_params = {}

    @staticmethod
    def expired():
        return False


def _run_cli(p, flag):
    args = [sys.executable, "-m", "autocrypt.cli", str(p), "--json", "--top", "5"]
    r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    if not r.stdout:
        return False, "no json output"
    import json
    try:
        out = json.loads(r.stdout)
    except Exception:
        return False, "bad json"
    for res in out.get("results", []):
        if flag.decode().lower() in res.get("plaintext", "").lower():
            return True, f"flag recovered at rank in {res.get('chain')}"
    return False, "flag not recovered"


def pipeline():
    txt, flag = make_challenge()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(txt, encoding="utf-8")
        return _run_cli(p, flag)


def main():
    ok, note = pipeline()
    print(f"lfsr-known-fields: {'PASS' if ok else 'FAIL'} ({note})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
