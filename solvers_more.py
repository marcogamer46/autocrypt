"""Extra compact solvers: more RSA cases, Rabin, Hill 2x2, Ook!, big-int -> bytes."""
from __future__ import annotations
import math, re, itertools
from core import solver
from scoring import assess, quadgram_score
import solvers as S


def _txt(d):
    try:
        return d.decode("ascii")
    except UnicodeDecodeError:
        return ""


def _vals(data, ctx):
    v = {}
    for k, x in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*(-?0x[0-9a-fA-F]+|-?\d+)", _txt(data)):
        v.setdefault(k.lower(), int(x, 0))
    for k, x in (ctx.rsa_params or {}).items():
        try:
            v.setdefault(k.lower(), int(x, 0) if isinstance(x, str) else int(x))
        except (ValueError, TypeError):
            pass
    return v


def _pick(v, *names):
    for n in names:
        if v.get(n):
            return v[n]


def _is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _sqrt_mod_p(a, p):  # p prime, returns a root or None
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2; s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p; i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def _rho(n, ctx, limit=3_000_000):
    """Brent's Pollard rho; returns a nontrivial factor or None."""
    if n % 2 == 0:
        return 2
    for cst in (1, 3, 5, 7):
        y, r, q, g, x, ys = 2, 1, 1, 1, 2, 2
        m = 512
        steps = 0
        while g == 1 and steps < limit:
            x = y
            for _ in range(r):
                y = (y * y + cst) % n
            k = 0
            # Batch many iterations into one gcd: accumulate the product of
            # |x-y| over a larger block (8x fewer gcd calls on average).
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + cst) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
            steps += r
            if ctx.expired():
                return None
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + cst) % n
                g = math.gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
    return None


# ----------------------------------------------------------- Lenstra ECM
# Pure-Python one-stage ECM (affine arithmetic). Each modular inverse that
# fails in the scalar multiplication reveals a nontrivial factor. Used as a
# last resort after p-1/p+1/rho on larger moduli (small factors ~<=45 digits).
_ECM_PRIMES_CACHE = None


def _ecm_primes(B1):
    global _ECM_PRIMES_CACHE
    if _ECM_PRIMES_CACHE is not None and _ECM_PRIMES_CACHE[0] == B1:
        return _ECM_PRIMES_CACHE[1]
    sieve = bytearray(b"\x01") * (B1 + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(B1 ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    primes = [i for i in range(2, B1 + 1) if sieve[i]]
    _ECM_PRIMES_CACHE = (B1, primes)
    return primes


def _ecm_step(P, Q, a, n, factorbox):
    """P + Q mod n (affine). If a denominator shares a factor with n, stash it."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % n == 0:
            return None
        return _ecm_double(P, a, n, factorbox)
    denom = (x2 - x1) % n
    g = math.gcd(denom, n)
    if g != 1:
        factorbox.append(g)
        return None
    lam = (y2 - y1) * pow(denom, -1, n) % n
    x3 = (lam * lam - x1 - x2) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3)


def _ecm_double(P, a, n, factorbox):
    x1, y1 = P
    denom = 2 * y1 % n
    g = math.gcd(denom, n)
    if g != 1:
        factorbox.append(g)
        return None
    lam = (3 * x1 * x1 + a) * pow(denom, -1, n) % n
    x3 = (lam * lam - 2 * x1) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3)


def _ecm_scalar(k, P, a, n, factorbox):
    R = None
    Q = P
    while k:
        if k & 1:
            R = _ecm_step(R, Q, a, n, factorbox)
            if factorbox:
                return None
        Q = _ecm_double(Q, a, n, factorbox)
        if factorbox:
            return None
        k >>= 1
    return R


def _ecm(n, ctx, B1=50000, max_curves=12):
    """Lenstra ECM stage 1. Returns a nontrivial factor or None.

    Pure-Python ECM is only cost-effective for small factors (~<= 48 bits):
    larger factors need B1/curve counts far beyond a normal per-solver budget.
    It is a last resort after p-1/p+1/rho. (The sympy factorint hook in
    factor_all remains the preferred full-featured ECM when available.)
    """
    if n.bit_length() < 96 or n.bit_length() > 300:
        return None
    import random as _random
    rng = _random.Random()
    primes = _ecm_primes(B1)
    k = 1
    for q in primes:
        e = 1
        while q ** (e + 1) <= B1:
            e += 1
        k *= q ** e
    for _ in range(max_curves):
        if ctx.expired():
            return None
        a = rng.randrange(1, n)
        x = rng.randrange(0, n)
        y = rng.randrange(0, n)
        b = (y * y - x * x * x - a * x) % n
        disc = (4 * a * a * a + 27 * b * b) % n
        g = math.gcd(disc, n)
        if 1 < g < n:
            return g
        if g == n:
            continue
        factorbox = []
        _ecm_scalar(k, (x, y), a, n, factorbox)
        if factorbox:
            g = factorbox[0]
            if 1 < g < n:
                return g
    return None


def _pm1(n, B=200_000):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        if j % 1000 == 0:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
    g = math.gcd(a - 1, n)
    return g if 1 < g < n else None


_PP1_M = None


def _pp1_moment():
    """M = product of q^floor(log_q B) over primes q <= B (B matches p-1)."""
    global _PP1_M
    if _PP1_M is None:
        B = 200_000
        sieve = bytearray(b"\x01") * (B + 1)
        sieve[0] = sieve[1] = 0
        for i in range(2, int(B ** 0.5) + 1):
            if sieve[i]:
                sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
        M = 1
        for q in (i for i in range(2, B + 1) if sieve[i]):
            e = 1
            while q ** (e + 1) <= B:
                e += 1
            M *= q ** e
        _PP1_M = M
    return _PP1_M


def _v_mod(P, M, n):
    """Lucas V_M(P,1) mod n by fast doubling of the pair (V_k, V_{k+1})."""
    vk, vk1 = 2 % n, P % n
    for bit in bin(M)[2:]:
        vk, vk1 = (vk * vk - 2) % n, (vk * vk1 - P) % n
        if bit == "1":
            vk, vk1 = vk1, (P * vk1 - vk) % n
    return vk


def _pp1(n, ctx):
    """Williams' p+1 (Lucas V_j(P,1)); returns a nontrivial factor or None.

    Recovers primes p where p+1 is B-smooth even when p-1 is not (safe primes,
    e.g.). Several bases P cover both signs of the quadratic character.
    """
    if n % 2 == 0:
        return 2
    M = _pp1_moment()
    for P in (2, 3, 5, 7, 11, 13, 17, 19):
        if ctx.expired():
            return None
        g = math.gcd(_v_mod(P, M, n) - 2, n)
        if 1 < g < n:
            return g
    return None


def factor_all(n, ctx):
    """Full factorisation {prime: exp}: trial division, p-1, p+1, rho, optional sympy ECM."""
    f, todo = {}, [n]
    for p in range(2, 100_000):
        if n % p == 0:
            while n % p == 0:
                f[p] = f.get(p, 0) + 1
                n //= p
    todo = [n] if n > 1 else []
    while todo:
        x = todo.pop()
        if x == 1:
            continue
        if _is_prime(x):
            f[x] = f.get(x, 0) + 1
            continue
        r = math.isqrt(x)
        if x.bit_length() <= 480:
            d = r if r * r == x else (_pm1(x) or _pp1(x, ctx) or _rho(x, ctx) or _ecm(x, ctx))
        else:
            # p-1/p+1/rho/ECM cannot meaningfully finish on huge moduli inside
            # a per-solver budget; falling through to sympy (if present) or
            # None is the only sane step.
            d = r if r * r == x else None
        if not d:
            try:
                from sympy import factorint
                for p, k in factorint(x, limit=10**9, use_ecm=True, use_pm1=False, use_rho=False).items():
                    f[int(p)] = f.get(int(p), 0) + k
                continue
            except Exception:
                pass
            return None
        todo += [d, x // d]
    return f


@solver("RSA-extra", lambda fp: .85 if fp["charset"] == "ascii-text" and (
    re.search(r"\b(?:n|N|modulus|p|q)\s*[:=]", fp.get("_text", ""))
    or len(re.findall(r"\b\d+\b", fp.get("_text", ""))) >= 4) else 0.0)
def solve_rsa_extra(data, ctx):
    """Given d / p+q / phi, prime n, prime power n, Rabin (e=2), padded small-e."""
    if ctx.depth > 0:
        return
    v = _vals(data, ctx)
    n = _pick(v, "n", "modulus")
    c = _pick(v, "c", "ct", "ciphertext", "cyphertext", "cypher", "enc", "cipher", "encrypted", "message", "msg")
    e = _pick(v, "e", "exponent") or 65537
    if not c:
        return
    p, q = _pick(v, "p"), _pick(v, "q")
    if not n and p and q:
        n = p * q
    if not n or n < 2:
        return
    seen = set()

    def out(m, how):
        if m is None or m < 0 or (how, m) in seen:
            return
        seen.add((how, m))
        pl = S._int_plain(m)
        yield pl, "RSA " + how, {"n_bits": n.bit_length()}, assess(pl)[0]

    # Explicit prime factors from source hints (p1..pN / q1..qN): if their
    # product equals the modulus, phi = prod(p-1) — no factoring needed.
    # Checked BEFORE factoring so a large modulus never costs a slice.
    given_primes = sorted({val for k, val in v.items() if re.fullmatch(r"(?:p|q)\d+", k)})
    if len(given_primes) >= 2 and math.prod(given_primes) == n:
        phi = 1
        for pp in given_primes:
            phi *= pp - 1
        if math.gcd(e, phi) == 1:
            yield from out(pow(c, pow(e, -1, phi), n),
                           f"known-multi-prime ({len(given_primes)} factors)")
            return
    # Multi-prime ("crowded") modulus: factor completely, phi = prod p^(k-1)(p-1).
    if not _is_prime(n):
        fa = factor_all(n, ctx)
        if fa and sum(fa.values()) > 2 or (fa and 2 in fa):
            phi = 1
            for pr, k in fa.items():
                phi *= pr ** (k - 1) * (pr - 1)
            if math.gcd(e, phi) == 1:
                yield from out(pow(c, pow(e, -1, phi), n), f"multi-prime ({sum(fa.values())} factors)")
    d = _pick(v, "d")
    if d:
        yield from out(pow(c, d, n), "known-d")
    if p and q and p * q == n:
        yield from out(pow(c, pow(e, -1, (p - 1) * (q - 1)), n), "known-p-q") if math.gcd(e, (p - 1) * (q - 1)) == 1 else iter(())
    phi = _pick(v, "phi", "totient")
    if phi and math.gcd(e, phi) == 1:
        yield from out(pow(c, pow(e, -1, phi), n), "known-phi")
    if p and not q and n % p == 0:
        q = n // p
        if math.gcd(e, (p - 1) * (q - 1)) == 1:
            yield from out(pow(c, pow(e, -1, (p - 1) * (q - 1)), n), "one-prime-given")
    if _is_prime(n):  # n prime -> phi = n-1
        if math.gcd(e, n - 1) == 1:
            yield from out(pow(c, pow(e, -1, n - 1), n), "prime-modulus")
    else:
        r = math.isqrt(n)
        if r * r == n and _is_prime(r) and math.gcd(e, r * (r - 1)) == 1:  # n = p^2
            yield from out(pow(c, pow(e, -1, r * (r - 1)), n), "square-modulus")
    # Even e (Rabin e=2, e=4, e=20...): e = 2^k * odd. Undo the odd part with an inverse
    # exponent, then take k modular square roots per prime and combine with CRT.
    if e % 2 == 0 and not _is_prime(n):
        f = S._factor(n, ctx)
        if f and _is_prime(f[0]) and _is_prime(f[1]):
            a, b = f
            k, odd = 0, e
            while odd % 2 == 0:
                odd //= 2; k += 1
            phi2 = (a - 1) * (b - 1)
            if math.gcd(odd, phi2) == 1 and k <= 6:
                cc = pow(c, pow(odd, -1, phi2), n) if odd > 1 else c
                def roots(x, pr):
                    cur = {x % pr}
                    for _ in range(k):
                        nxt = set()
                        for y in cur:
                            r = _sqrt_mod_p(y, pr)
                            if r is not None:
                                nxt.update({r, pr - r})
                        cur = nxt
                    return cur
                ra, rb = roots(cc, a), roots(cc, b)
                cands = []
                for x in ra:
                    for y in rb:
                        m = S._crt([x, y], [a, b])
                        pl = S._int_plain(m) if m is not None else b""
                        if pl:
                            cands.append((assess(pl)[0], m))
                cands.sort(reverse=True)
                for _, m in cands[:6]:
                    yield from out(m, "even-e roots" if e != 2 else "rabin")
    # e shared factor with phi (e.g. e=2/4): try gcd-reduced exponent after factoring
    if not _is_prime(n):
        f = S._factor(n, ctx)
        if f:
            a, b = f
            phi = (a - 1) * (b - 1)
            g = math.gcd(e, phi)
            if 1 < g <= 64 and e != 2:
                try:
                    d2 = pow(e // g, -1, phi)
                    mg = pow(c, d2, n)
                    r = S._integer_root(mg, g)
                    if r is not None:
                        yield from out(r, "gcd-exponent")
                except ValueError:
                    pass
    # small e with slight padding: m^e = c + k*n
    if e <= 7 and c < n:
        for k in range(1, 200_000):
            if ctx.expired():
                break
            r = S._integer_root(c + k * n, e)
            if r is not None:
                yield from out(r, "small-e wraparound")
                break


# ---------------------------------------------------------------- Hill 2x2
_A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


@solver("hill-2x2", lambda fp: .30 if fp["charset"] == "ascii-text" and re.fullmatch(
    r"[A-Za-z\s]{8,400}", fp.get("_text", "") or "-") else 0.0)
def solve_hill2(data, ctx):
    t = _txt(data)
    L = [ord(ch) - 65 for ch in t.upper() if ch.isalpha()]
    if len(L) < 12 or len(L) % 2:
        return
    pairs = [(L[i], L[i + 1]) for i in range(0, len(L), 2)]
    best = []
    for a, b, c, d in itertools.product(range(26), repeat=4):
        if (a * 26 * 26 * 26 + b * 26 * 26 + c * 26 + d) % 4096 == 0 and ctx.expired():
            return
        det = (a * d - b * c) % 26
        if det % 2 == 0 or det % 13 == 0:
            continue
        di = pow(det, -1, 26)
        ia, ib, ic, id_ = d * di % 26, -b * di % 26, -c * di % 26, a * di % 26
        # cheap prefilter on first 6 pairs: reject if too many rare letters (J Q X Z)
        s = "".join(_A[(ia * x + ib * y) % 26] + _A[(ic * x + id_ * y) % 26] for x, y in pairs[:6])
        if sum(ch in "JQXZ" for ch in s) > 1:
            continue
        best.append((quadgram_score(s), (ia, ib, ic, id_)))
    best.sort(reverse=True)
    full = []
    for _, (ia, ib, ic, id_) in best[:12]:
        s = "".join(_A[(ia * x + ib * y) % 26] + _A[(ic * x + id_ * y) % 26] for x, y in pairs)
        full.append((quadgram_score(s), s, (ia, ib, ic, id_)))
    full.sort(reverse=True)
    for i, (qs, s, key) in enumerate(full[:5]):
        sc = assess(s.lower().encode())[0]
        if i == 0 and (len(full) < 2 or qs - full[1][0] > .25):
            sc = max(sc, .65)   # clear winner by quadgram margin
        yield s.lower().encode(), "hill-2x2", {"inv_key": list(key)}, sc


# ---------------------------------------------------------------- Ook!
@solver("ook", lambda fp: .6 if fp["charset"] == "ascii-text" and "Ook" in fp.get("_text", "") else 0.0)
def solve_ook(data, ctx):
    toks = re.findall(r"Ook([.!?])", _txt(data))
    if len(toks) < 2:
        return
    m = {(".", "."): "+", ("!", "!"): "-", (".", "!"): ">", ("!", "."): "<",
         ("!", "?"): "[", ("?", "!"): "]", (".", "?"): "", ("?", "."): ".", ("?", "?"): ""}
    bf = "".join(m.get((toks[i], toks[i + 1]), "") for i in range(0, len(toks) - 1, 2))
    # swap '.'(output) properly: Ook? Ook. is output
    yield bf.encode(), "ook->brainfuck", {}, .4


# ---------------------------------------------------------------- big int
@solver("integer-to-bytes", lambda fp: .5 if fp["charset"] == "ascii-text" and re.fullmatch(
    r"(?:0x)?[0-9a-fA-F]{20,}", (fp.get("_text", "") or "-").strip()) else 0.0)
def solve_bigint(data, ctx):
    t = _txt(data).strip()
    cands = []
    if t.isdigit():
        cands.append(int(t))
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", t):
        cands.append(int(t, 16))
    for n in cands:
        pl = S._int_plain(n)
        yield pl, "integer-to-bytes", {}, assess(pl)[0]


# ---------------------------------------------------------------- LFSR
def _bm(s):
    """Berlekamp-Massey over GF(2). Returns (L, connection poly list c[0..L], c[0]=1)."""
    n = len(s)
    c, b = [1] + [0] * n, [1] + [0] * n
    L, m = 0, -1
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            d ^= c[j] & s[i - j]
        if d:
            t = c[:]
            shift = i - m
            for j in range(n + 1 - shift):
                c[j + shift] ^= b[j]
            if 2 * L <= i:
                L, m, b = i + 1 - L, i, t
    return L, c[:L + 1]


def _bits(bs, msb):
    out = []
    for x in bs:
        r = range(7, -1, -1) if msb else range(8)
        out += [(x >> k) & 1 for k in r]
    return out


def _frombits(bits, msb):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for k, bit in enumerate(bits[i:i + 8]):
            v |= bit << (7 - k if msb else k)
        out.append(v)
    return bytes(out)


@solver("lfsr-known-plaintext", lambda fp: .35 if fp["length"] >= 12 else 0.0)
def solve_lfsr(data, ctx):
    """Keystream = ct XOR crib -> Berlekamp-Massey -> rebuild LFSR -> decrypt the rest.
    Works for any LFSR/XOR stream cipher when a crib (flag prefix) is known."""
    if ctx.depth > 1 or len(data) < 12:
        return
    if sum(32 <= b < 127 for b in data[:64]) > .9 * min(64, len(data)):
        return   # already printable text: not a stream-cipher ciphertext
    cribs = [c for c in [ctx.known_plaintext, "flag{", "FLAG{", "picoCTF{", "CTF{", "ctf{",
                         "HTB{", "academy{", "THM{", "flag is ", "The flag"] if c]
    seen = set()
    for crib in cribs:
        cb = crib.encode()
        if len(cb) < 4 or len(cb) > len(data):
            continue
        for msb in (True, False):
            ks = [a ^ b for a, b in zip(_bits(data[:len(cb)], msb), _bits(cb, msb))]
            L, c = _bm(ks)
            if L == 0 or 2 * L + 8 > len(ks) or L > 128:
                continue   # need slack bits to trust the recovered register
            total = len(data) * 8
            seq = ks[:]
            for i in range(len(ks), total):
                v = 0
                for j in range(1, L + 1):
                    if c[j]:
                        v ^= seq[i - j]
                seq.append(v)
            pl = bytes(a ^ b for a, b in zip(data, _frombits(seq, msb)))
            if pl in seen:
                continue
            seen.add(pl)
            pr = sum(32 <= x < 127 or x in (9, 10, 13) for x in pl) / len(pl)
            if pr >= .95:
                conf = 1 - len(pl) * (95 / 256) ** (len(pl) // 2)
                yield pl, f"Cracked LFSR (L={L}, crib={crib!r}, {'msb' if msb else 'lsb'})", {
                    "_statistical": True}, max(.7, min(.99, conf))


# ------------------------------------------- Franklin-Reiter related messages
def _pmod(a, b, N):
    """a mod b for polynomials over Z_N (low->high). None if lead coeff not invertible."""
    a = a[:]
    inv = pow(b[-1], -1, N) if math.gcd(b[-1], N) == 1 else None
    if inv is None:
        return None
    while len(a) >= len(b):
        q = a[-1] * inv % N
        s = len(a) - len(b)
        for i, x in enumerate(b):
            a[s + i] = (a[s + i] - q * x) % N
        a.pop()
    while a and a[-1] == 0:
        a.pop()
    return a


def _fr_gcd(f, g, N):
    while g:
        r = _pmod(f, g, N)
        if r is None:
            return None
        f, g = g, r
    return f


def _int_tokens(t):
    toks = t.split()
    if 4 <= len(toks) <= 8 and all(re.fullmatch(r"-?\d+", x) for x in toks):
        return [int(x) for x in toks]
    return None


def _related_prior(fp):
    t = fp.get("_text", "")
    if fp["charset"] != "ascii-text":
        return 0.0
    if _int_tokens(t) or all(re.search(rf"\b{k}\s*=", t) for k in ("c1", "c2", "n")):
        return .999
    return 0.0


@solver("RSA-related-message", _related_prior)
def solve_related(data, ctx):
    """Franklin-Reiter: c1=m^e, c2=(m-d)^e mod N with the small difference d leaked
    (unlabeled 'c1 c2 diff N', or labeled c1/c2/diff|delta|r/n/e)."""
    if ctx.depth > 0:
        return
    t = _txt(data)
    v = _vals(data, ctx)
    nums = _int_tokens(t)
    N = c1 = c2 = diff = None
    if nums:
        N = max(nums)
        small = [x for x in nums if abs(x) < 1 << 64]
        big = [x for x in nums if abs(x) >= 1 << 64 and x != N]
        if len(small) >= 1 and len(big) >= 2:
            diff, (c1, c2) = small[0], big[:2]
    else:
        N = _pick(v, "n", "modulus")
        c1, c2 = _pick(v, "c1", "ciphertext1", "ct1"), _pick(v, "c2", "ciphertext2", "ct2")
        diff = next((v[k] for k in ("diff", "delta", "r", "d") if k in v), None)
    if not all(x is not None for x in (N, c1, c2, diff)):
        return
    es = [v["e"]] if v.get("e") else [17, 3, 5, 7, 11, 257, 13, 9, 15, 19, 21, 23, 25, 27]
    es = [e for e in es if e <= 1025]
    for e in es:
        if ctx.expired():
            return
        for sign in (1, -1):               # Message - Message_fixed = diff (either order)
            dd = diff * sign
            f1 = [(-c1) % N] + [0] * (e - 1) + [1]
            f2 = [0] * (e + 1)             # (x - dd)^e - c2
            for k in range(e + 1):
                f2[k] = math.comb(e, k) * pow(-dd, e - k, N) % N
            f2[0] = (f2[0] - c2) % N
            g = _fr_gcd(f1, f2, N)
            if g and len(g) == 2 and math.gcd(g[1], N) == 1:
                m = -g[0] * pow(g[1], -1, N) % N
                pl = S._int_plain(m)
                if assess(pl)[0] > .2 or sum(32 <= x < 127 for x in pl) >= .9 * len(pl):
                    # both messages are recovered; the leaked difference links them
                    for mm, nm in ((m - dd, "fixed"), (m, "original")):
                        if mm > 0:
                            yield S._int_plain(mm), f"RSA Franklin-Reiter related message {nm} (e={e})", {}, .95
                    return
