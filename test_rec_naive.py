#!/usr/bin/env python3
"""Naive-recurrence check for the G2 fast matrix path."""
import sys, random
sys.path.insert(0, "/home/chillinmalware/Documents/autocrypt")
from solvers import _g2_recurrence

def naive(rec, N, M):
    k = max(rec["coeffs"].keys())
    vals = [rec["bases"].get(i, 0) for i in range(k)]
    for i in range(k, N + 1):
        vals.append(sum(rec["coeffs"].get(d, 0) * vals[i - d] for d in rec["coeffs"]) + rec["const"])
    return vals[N] % M

rng = random.Random(7)
for trial in range(20):
    k = rng.randint(1, 4)
    coeffs = {d: rng.randint(-9, 9) for d in range(1, k + 1)}
    const = rng.randint(0, 5)
    bases = {i: rng.randint(1, 9) for i in range(k)}
    rec = dict(name="f", arg="i", bases=bases, coeffs=coeffs, const=const)
    N = rng.randint(k, 120)
    M = 10 ** rng.randint(3, 6)
    a = _g2_recurrence(rec, N, M)
    b = naive(rec, N, M)
    assert a == b, (trial, a, b)
print("REC_NAIVE: 20/20 OK")
