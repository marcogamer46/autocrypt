#!/usr/bin/env python3
"""Regression tests for the RSA identity (e=1) and Rabin (e=2) solver branches.

Directly exercises `solvers.solve_rsa` with constructed n/e/c inputs and verifies
the plaintext is recovered. Run with the project venv:

    python test_rsa_extra.py
"""
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import solvers  # noqa: E402


class _Ctx:
    """Minimal solver context (only the bits solve_rsa touches)."""
    BUDGET = 120.0

    def __init__(self):
        self.rsa_params = {}
        self.depth = 0
        self.t0 = time.time()

    def expired(self):
        return (time.time() - self.t0) > self.BUDGET

    def record_bug(self, *a):
        pass


def _prime(rnd, bits):
    while True:
        x = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if pow(2, x - 1, x) == 1 and x % 3 != 0 and x % 5 != 0:
            return x


def _gen_semiprime(nbits, seed):
    rnd = random.Random(seed)
    h = nbits // 2
    p, q = _prime(rnd, h), _prime(rnd, h)
    if p == q:
        q = _prime(rnd, h)
    return p, q, p * q


def _recovered(results):
    """Set of all plaintext bytes yielded by solve_rsa."""
    out = set()
    for plain, _method, _params, _score in results:
        out.add(plain)
    return out


def _plain_bytes(m):
    """Byte encoding solvers uses for an integer plaintext (big-endian)."""
    return m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")


def test_e_equals_one():
    # e=1 is the identity: c == m (mod n); with m < n we get m back directly.
    p, q, n = _gen_semiprime(400, 1)
    m = int.from_bytes(b"academy{e_equals_one}", "big")
    assert m < n, "test setup: message must fit under modulus"
    c = m  # pow(m, 1, n) == m when m < n
    data = f"n = {n}\ne = 1\nc = {c}".encode()
    results = list(solvers.solve_rsa(data, _Ctx()))
    assert _plain_bytes(m) in _recovered(results), "e=1 plaintext not recovered"
    assert any(meth == "RSA e=1" for _p, meth, _pa, _s in results), \
        "e=1 branch not exercised"


def test_rabin():
    # Rabin (e=2). Use m ≈ n so the small-e "overflow cube-root" scan (bounded
    # at 4096 i) cannot short-circuit, forcing the factoring → Rabin-sqrt path.
    p, q, n = _gen_semiprime(80, 2)
    m = n - 123457  # < n, and (m*m - c)//n is huge → overflow scan skipped
    c = pow(m, 2, n)
    data = f"n = {n}\ne = 2\nc = {c}".encode()
    results = list(solvers.solve_rsa(data, _Ctx()))
    recovered = _recovered(results)
    assert _plain_bytes(m) in recovered, \
        f"Rabin plaintext not recovered; got {sorted(len(x) for x in recovered)}"
    assert any(meth.startswith("RSA Rabin") for _p, meth, _pa, _s in results), \
        "Rabin sqrt branch not exercised"


def main():
    t = time.time()
    test_e_equals_one()
    test_rabin()
    print(f"PASS test_rsa_extra (e=1, Rabin) in {time.time() - t:.1f}s")


if __name__ == "__main__":
    main()
