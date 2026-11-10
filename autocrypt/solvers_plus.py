"""More techniques: shared-prime RSA, dp/dq leak, discrete log (BSGS + Pohlig-Hellman),
LCG recovery, MT19937 prediction, hash cracking, ECB detection."""
from __future__ import annotations
import hashlib
import itertools
import math
import random
import re
import string

from autocrypt.core import solver
from autocrypt.scoring import assess, WORDS
import autocrypt.solvers as S
import autocrypt.solvers_more as SM  # module namespace (late-bound) breaks an import cycle:
# test_* may import autocrypt.solvers_more first -> solvers -> solvers_plus -> solvers_more
# (still partial). Referencing SM.<name> at call time avoids needing the names
# to exist while the module is only partially initialized.


def _ints(t, lo=None, hi=None):
    toks = t.split()
    if toks and all(re.fullmatch(r"-?\d+", x) for x in toks):
        v = [int(x) for x in toks]
        if all((lo is None or x >= lo) and (hi is None or x < hi) for x in v):
            return v
    return None


def _plain(m):
    return S._int_plain(m)


# ------------------------------------------------ RSA: shared prime / dp leak
@solver("RSA-shared-prime", lambda fp: .999 if fp["charset"] == "ascii-text" and len(
    re.findall(r"\bn\d+\s*[:=]", fp.get("_text", ""))) >= 2 else 0.0)
def solve_shared_prime(data, ctx):
    v = SM._vals(data, ctx)
    ns = {k[1:]: x for k, x in v.items() if re.fullmatch(r"n\d+", k)}
    e = v.get("e", 65537)
    for (i, a), (j, b) in itertools.combinations(sorted(ns.items()), 2):
        g = math.gcd(a, b)
        if 1 < g < min(a, b):
            for idx, n in ((i, a), (j, b)):
                c = v.get("c" + idx)
                if c:
                    p = g
                    q = n // p
                    phi = (p - 1) * (q - 1)
                    if math.gcd(e, phi) == 1:
                        pl = _plain(pow(c, pow(e, -1, phi), n))
                        yield pl, f"RSA shared-prime gcd(n{i},n{j})", {}, assess(pl)[0]


@solver("RSA-dp-leak", lambda fp: .999 if fp["charset"] == "ascii-text" and re.search(
    r"\bd[pq]\s*=", fp.get("_text", ""), re.I) else 0.0)
def solve_dp_leak(data, ctx):
    v = SM._vals(data, ctx)
    n, c, e = SM._pick(v, "n"), SM._pick(v, "c", "ct", "enc", "cyphertext", "ciphertext"), v.get("e", 65537)
    leak = SM._pick(v, "dp", "dq")
    if not (n and c and leak):
        return
    for base in (2, 3, 5, 7):
        p = math.gcd(pow(base, e * leak, n) - base, n)
        if 1 < p < n:
            q = n // p
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) == 1:
                pl = _plain(pow(c, pow(e, -1, phi), n))
                yield pl, "RSA dp/dq leak (CRT-RSA)", {}, assess(pl)[0]
                return


# ------------------------------------------------ discrete log
def _bsgs(g, h, p, order):
    m = math.isqrt(order) + 1
    tbl, cur = {}, 1
    for j in range(m):
        tbl.setdefault(cur, j)
        cur = cur * g % p
    f, gi = h % p, pow(g, -m, p)
    for i in range(m + 1):
        if f in tbl:
            return i * m + tbl[f]
        f = f * gi % p
    return None


def dlog(g, h, p, ctx):
    """x with g^x = h mod p; Pohlig-Hellman over the factors of p-1 (needs smooth-ish p-1)."""
    fa = SM.factor_all(p - 1, ctx)
    if not fa:
        return None
    res, mods = [], []
    for q, k in fa.items():
        if q > 1 << 40:
            return None
        qk = q ** k
        gq, hq = pow(g, (p - 1) // qk, p), pow(h, (p - 1) // qk, p)
        gam, x = pow(gq, q ** (k - 1), p), 0
        for i in range(k):
            hk = pow(pow(gq, -x, p) * hq % p, q ** (k - 1 - i), p)
            d = _bsgs(gam, hk, p, q)
            if d is None:
                return None
            x += d * q ** i
        res.append(x)
        mods.append(qk)
        if ctx.expired():
            return None
    x = S._crt(res, mods)
    return x if x is not None and pow(g, x, p) == h % p else None


@solver("discrete-log", lambda fp: .85 if fp["charset"] == "ascii-text" and re.search(
    r"\bg\s*=", fp.get("_text", "")) and re.search(r"\bp\s*=", fp.get("_text", "")) else 0.0)
def solve_dlog(data, ctx):
    """g^x = h (mod p) with smooth p-1 (or small p). Also derives the DH shared secret."""
    v = SM._vals(data, ctx)
    g, p = v.get("g"), v.get("p")
    if not (g and p) or p < 5 or not SM._is_prime(p):
        return
    pubs = {k: x for k, x in v.items() if k in ("a", "b", "h", "y", "pub", "public", "x") and 1 < x < p}
    pubs.update({k: x for k, x in v.items() if k in ("a_pub", "b_pub", "pk", "alice", "bob") and 1 < x < p})
    sol, lines = {}, []
    for k, h in pubs.items():
        x = dlog(g, h, p, ctx)
        if x is not None:
            sol[k] = x
            lines.append(f"log_g({k}) = {x}")
    for (k1, x1), (k2, h2) in itertools.product(sol.items(), pubs.items()):
        if k1 < k2 and k2 in sol or (k1 != k2 and k2 not in sol):
            lines.append(f"shared secret g^({k1}*{k2}) = {pow(h2, x1, p)}")
    if lines:
        yield "\n".join(lines).encode(), "Cracked discrete log / DH", {"_statistical": True}, .98


# ------------------------------------------------ LCG / MT19937
@solver("lcg-recovery", lambda fp: .8 if fp["charset"] == "ascii-text" and (_ints(fp.get("_text", ""), 0, 1 << 128) or [])
        and 6 <= len(fp.get("_text", "").split()) < 600 else 0.0)
def solve_lcg(data, ctx):
    s = _ints(SM._txt(data), 0, 1 << 128)
    if not s or len(s) < 6 or len(s) >= 624:
        return
    d = [s[i + 1] - s[i] for i in range(len(s) - 1)]
    u = [d[i + 2] * d[i] - d[i + 1] ** 2 for i in range(len(d) - 2)]
    m = 0
    for x in u:
        m = math.gcd(m, x)
    m = abs(m)
    if m <= max(s):
        return
    for tries in range(len(s) - 2):
        den = (s[tries + 1] - s[tries]) % m
        g = math.gcd(den, m)
        if g == 1:
            a = (s[tries + 2] - s[tries + 1]) * pow(den, -1, m) % m
            break
    else:
        return
    c = (s[1] - a * s[0]) % m
    if any((a * s[i] + c) % m != s[i + 1] for i in range(len(s) - 1)):
        return
    nxt, cur = [], s[-1]
    for _ in range(5):
        cur = (a * cur + c) % m
        nxt.append(cur)
    prev = (s[0] - c) * pow(a, -1, m) % m if math.gcd(a, m) == 1 else None
    out = f"modulus={m} multiplier={a} increment={c}\nnext: {nxt}\nprevious state: {prev}"
    yield out.encode(), "Cracked LCG parameters", {"m": m, "a": a, "c": c, "_statistical": True}, .98



# ------------------------------------------------ hashes
_HASH = {32: ("md5",), 40: ("sha1",), 56: ("sha224",), 64: ("sha256", "sha3_256"),
         96: ("sha384",), 128: ("sha512",)}



# ------------------------------------------------ ECB detection
@solver("ecb-detect", lambda fp: .3 if fp["length"] >= 32 else 0.0)
def solve_ecb(data, ctx):
    raw = data
    t = SM._txt(data).strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", t):
        raw = bytes.fromhex(t)
    if len(raw) % 16 == 0 and len(raw) >= 32:
        blocks = [raw[i:i + 16] for i in range(0, len(raw), 16)]
        if len(set(blocks)) < len(blocks):
            ctx.findings.append(f"AES-ECB likely: {len(blocks) - len(set(blocks))} repeated 16-byte "
                                "blocks (byte-at-a-time / block-shuffle attacks apply)")
    return
    yield
