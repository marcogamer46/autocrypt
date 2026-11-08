#!/usr/bin/env python3
"""Partial-p (Coppersmith) regression tests: balanced and unbalanced primes.

Directly exercises `solvers._recover_p_partial` (the sweep) and the lattice
machinery across many random keys / leak sizes. Run with the project venv:

    python test_partial_p.py
"""
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import solvers  # noqa: E402


class _Ctx:
    """Time-budgeted context so expensive lattice escalation aborts cleanly."""
    BUDGET = 120.0

    def __init__(self):
        self.t0 = time.time()

    def expired(self):
        return (time.time() - self.t0) > self.BUDGET


def _prime(rnd, bits):
    while True:
        x = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if pow(2, x - 1, x) == 1 and x % 3 != 0 and x % 5 != 0:
            return x


def gen_key(nbits, pbits, m, seed):
    rnd = random.Random(seed)
    p = _prime(rnd, pbits)
    q = _prime(rnd, nbits - pbits)
    n = p * q
    return n, p, p >> m


def run_case(nbits, pbits, m, seed):
    n, p, p_high = gen_key(nbits, pbits, m, seed)
    t = time.time()
    rec = solvers._recover_p_partial(n, p_high, _Ctx())
    dt = time.time() - t
    if rec == p:
        return True, dt
    if rec is None:
        return False, dt
    return False, dt  # wrong p returned


def main():
    cases = [
        # (nbits, pbits, m, seed)
        (512, 256, 64, 1),
        (512, 256, 80, 2),
        (768, 384, 96, 3),
        (768, 384, 128, 4),
        (1024, 512, 96, 5),
        (1024, 512, 128, 6),
        (1024, 512, 160, 7),
        (1024, 512, 192, 8),
        # unbalanced p ~ n^0.60
        (768, 460, 128, 9),
        (853, 512, 160, 10),
        (1024, 614, 192, 11),
        # unbalanced p ~ n^0.55
        (1024, 563, 160, 12),
        (1024, 563, 180, 13),
    ]
    passed = 0
    for nbits, pbits, m, seed in cases:
        ok, dt = run_case(nbits, pbits, m, seed)
        status = "PASS" if ok else "FAIL"
        print(f"{status} nbits={nbits} pbits={pbits} m={m} seed={seed} "
              f"({dt:.1f}s)")
        if ok:
            passed += 1
    total = len(cases)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
