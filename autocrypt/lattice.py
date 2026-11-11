"""Lattice toolkit for autocrypt.

Implements:
  * LLL basis reduction (Lenstra–Lenstra–Lovász) over the integers.
  * Coppersmith's method (univariate, divisor-p formulation) used to recover the
    unknown low bits of a prime factor p of n when its high bits are known.

This is the machinery behind the ``RSA partial-p (Coppersmith)`` solver.
Only integer arithmetic and the standard library are used (``gmpy2`` is
optional). All algorithms are deterministic.
"""
from __future__ import annotations

import math

import autocrypt.czroots as czroots

# Rational arithmetic for Gram–Schmidt. gmpy2's mpq is ~5x faster than the
# fractions.Fraction implementation on the big-integer lattices used by
# Coppersmith; fall back to Fraction if gmpy2 is unavailable.
try:
    from gmpy2 import mpq as _Q
except Exception:  # pragma: no cover
    from fractions import Fraction as _Q

__all__ = ["lll", "coppersmith_partial_p"]

# ---------------------------------------------------------------------------
# LLL
# ---------------------------------------------------------------------------

def lll(basis, delta=0.75, check=None):
    """Reduce the integer lattice basis `basis` (list of integer rows) with LLL.

    `check` is an optional zero-arg callable; if it returns falsy, reduction
    aborts and returns None (used to respect the solver's deadline during a
    long high-dimension reduction).
    """
    B = [list(map(int, row)) for row in basis]
    n = len(B)
    if n < 2:
        return B
    m = len(B[0])

    Q = _Q
    half = Q(1, 2)
    deltaQ = Q(delta)

    Bstar = [[Q(0)] * m for _ in range(n)]
    mu = [[Q(0)] * n for _ in range(n)]
    norm = [Q(0)] * n

    def gso_range(start):
        """Recompute B*/mu/norm for rows start..n-1 (dependencies unchanged)."""
        for i in range(start, n):
            bi = B[i]
            bstar = [Q(x) for x in bi]
            for j in range(i):
                num = sum(bi[c] * Bstar[j][c] for c in range(m))
                den = norm[j]
                mui = (num / den) if den else Q(0)
                mu[i][j] = mui
                if mui:
                    bj = Bstar[j]
                    for c in range(m):
                        bstar[c] -= mui * bj[c]
            Bstar[i] = bstar
            norm[i] = sum(bstar[c] ** 2 for c in range(m))

    gso_range(0)

    k = 1
    while k < n:
        if check is not None and not check():
            return None
        # size-reduce B[k] against B[0..k-1]
        changed = False
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > half:
                q = round(mu[k][j])
                if q:
                    changed = True
                    for c in range(m):
                        B[k][c] -= q * B[j][c]
                    for l in range(j + 1):
                        mu[k][l] -= q * mu[j][l]
        # The reduction modified B[k]; the orthogonalization of rows below k
        # is now stale, so recompute the GSO suffix to keep it consistent.
        if changed:
            gso_range(k)
        # Lovász condition
        if norm[k] >= (deltaQ - mu[k][k - 1] ** 2) * norm[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            gso_range(k - 1)
            if k > 1:
                k -= 1
    return [[int(x) for x in row] for row in B]

# ---------------------------------------------------------------------------
# Small-integer polynomial root finding is provided by ``czroots``
# (Cantor-Zassenhaus splitting modulo a large prime). It handles polynomials
# with very large coefficients, which the CRT-based candidate enumeration can
# not (its residue combinations explode combinatorially).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Coppersmith: known high bits of p
# ---------------------------------------------------------------------------

def coppersmith_partial_p(n, p_high, m, mm=3, tt=1, check=None, escalate=True,
                           max_escalate=None):
    """Recover a prime factor p of n given its high bits.

    p = (p_high << m) + x,  with 0 <= x < 2^m.
    Returns p (an integer divisor of n) or None.

    This is Coppersmith's univariate method specialised to the linear
    polynomial f(x) = x + p_high*2^m whose small root x satisfies f(x) | n
    (x is the unknown low part of p). The lattice bound requires
    2^m < n^(beta^2) where beta = log_n(p); balanced RSA (p ~ n^0.5) yields
    beta^2 = 0.25, so m < 0.25*log2(n).

    A small dimension (mm=3, tt=1) is tried first — with gmpy2-backed LLL this
    is fast and succeeds for balanced primes — and the dimension is escalated
    automatically if the short vector does not yield a factor, so harder
    parameter regimes still succeed without paying the cost on easy ones.
    """
    a = p_high << m
    X = 1 << m

    # quick sanity: a factors n already
    g = math.gcd(a, n)
    if 1 < g < n:
        return g

    # Escalation ladder: (mm, tt) try in order of increasing lattice size.
    # When escalate=False the caller (e.g. the hypothesis sweep in
    # _recover_p_partial) wants a single cheap low-dimension attempt per m.
    if escalate:
        ladder = [(mm, tt), (mm + 1, tt + 1), (mm + 2, tt + 2), (mm + 3, tt + 3)]
    else:
        ladder = [(mm, tt)]
    if max_escalate is not None:
        ladder = ladder[:max_escalate]
    seen = set()
    for mmc, ttc in ladder:
        key = (mmc, ttc)
        if key in seen or mmc < 1 or ttc < 0:
            continue
        seen.add(key)
        p = _coppersmith_try(n, a, X, mmc, ttc, check)
        if p is not None:
            return p
        if check is not None and not check():
            return None
    return None


def _coppersmith_try(n, a, X, mm, tt, check):
    """One-shot Coppersmith construction for the given lattice dimension."""
    rows = []
    total_i = mm + tt
    nb_cols = total_i + 1

    # precompute powers of a and N
    a_pow = [1] * (total_i + 1)
    for i in range(1, total_i + 1):
        a_pow[i] = a_pow[i - 1] * a
    N_pow = [1] * (mm + 1)
    for i in range(1, mm + 1):
        N_pow[i] = N_pow[i - 1] * n

    for i in range(mm + 1):
        row = [0] * nb_cols
        scale = N_pow[mm - i]
        coeff = 1  # C(i,0)
        for j in range(i + 1):
            if j > 0:
                coeff = coeff * (i - j + 1) // j
            c = scale * coeff * a_pow[i - j]
            row[j] = c * X ** j
        rows.append(row)
    for i in range(mm + 1, mm + tt + 1):
        row = [0] * nb_cols
        coeff = 1
        for j in range(i + 1):
            if j > 0:
                coeff = coeff * (i - j + 1) // j
            c = coeff * a_pow[i - j]
            row[j] = c * X ** j
        rows.append(row)

    # trim to square by dropping empty trailing columns if any
    dim = len(rows)
    while dim > 0 and all(r[-1] == 0 for r in rows):
        for r in rows:
            r.pop()
        dim -= 1

    reduced = lll(rows, check=check)
    if reduced is None:
        return None  # aborted by deadline check

    # Try several shortest vectors; each yields an H(r) = 0 polynomial.
    # Reset the degree per vector — the while-loop below shrinks D, and
    # carrying that shrink into the next vector would read/misindex its H.
    for vec in reduced[:6]:
        D = len(reduced[0]) - 1  # max degree in scaled variable
        H = [0] * (D + 1)
        for k in range(D + 1):
            H[k] = vec[k] * X ** (D - k)
        while D > 0 and H[D] == 0:
            D -= 1
            H.pop()
        if D < 1:
            continue
        roots = czroots.find_roots(H, X)
        for r in roots:
            cand = a + r
            if cand <= 1:
                continue
            g = math.gcd(cand, n)
            if 1 < g < n:
                return g
    return None
