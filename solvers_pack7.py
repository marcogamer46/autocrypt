"""Pack 7: literal parsers, radix-ascii, reverse transforms, DSA/CRT/shared-prime
RSA, LCG/MT19937, DH-DLP, RC4/AES glue, hash cracking, classical improvements,
extra encodings, WAV LSB."""
from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import itertools
import math
import re
import struct

from core import solver
from scoring import assess, flag_plausibility, quadgram_score, english_confidence
import solvers as S
from solvers_more import _is_prime, factor_all

_EN_FREQ26 = [.08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094,
              .06966, .00153, .00772, .04025, .02406, .06749, .07507, .01929,
              .00095, .05987, .06327, .09056, .02758, .00978, .02360, .00150,
              .01974, .00074]


def _bytes_literal(text):
    """Extract a Python bytes literal (b'...' / b"..." with \\x escapes)."""
    for m in re.finditer(r"b(?P<q>['\"])(?P<v>.*?)(?P=q)", text, re.S):
        try:
            out = ast.literal_eval("b" + m.group("q") + m.group("v") + m.group("q"))
            if isinstance(out, bytes):
                return out
        except (ValueError, SyntaxError, MemoryError):
            pass
    return None


def _int_list(text):
    for m in re.finditer(r"\[\s*[0-9xXa-fA-F,\s]+\s*\]", text):
        try:
            val = ast.literal_eval(m.group(0))
        except (ValueError, SyntaxError):
            continue
        if isinstance(val, (list, tuple)) and val and all(isinstance(x, int) for x in val):
            if all(0 <= x <= 255 for x in val):
                return bytes(val)
    return None


def _hexdump(text):
    out = bytearray()
    for line in text.splitlines():
        m = re.match(r"^[0-9a-fA-F]{8}:\s*((?:[0-9a-fA-F]{2}\s*)+)", line)
        if m:
            for tok in m.group(1).split():
                try:
                    out.append(int(tok, 16))
                except ValueError:
                    return None
    return bytes(out) if out else None


def _literal_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    if re.search(r"\bb['\"]", t) or re.search(r"\[\s*[0-9xXa-fA-F,\s]+\s*\]", t) \
            or re.search(r"^[0-9a-fA-F]{8}:\s*(?:[0-9a-fA-F]{2}\s*)+", t, re.M):
        return .85
    return 0.0


@solver("bytes-literal", _literal_prior)
def solve_literal(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    out = _bytes_literal(text) or _int_list(text) or _hexdump(text)
    if out:
        score, _ = assess(out)
        yield out, "bytes-literal", {}, score


# -------------------------------------------------------------- CRT + radix
def _crt_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    mods = re.findall(r"\bmod\s*(\d+)", t, re.I)
    if len(mods) < 8:
        return 0.0
    return .8


@solver("crt", _crt_prior)
def solve_crt(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    pairs = []
    for m in re.finditer(r"\b(?:x|r|residue)\s*[:=]\s*(\d+)\s*(?:mod|modulus)?\s*[:=]?\s*(\d+)", text, re.I):
        r, mod = int(m.group(1)), int(m.group(2))
        if mod > 1 and 0 <= r < mod:
            pairs.append((r, mod))
    if len(pairs) < 8:
        # fallback: consecutive r/m tokens
        nums = [int(x) for x in re.findall(r"\d+", text)]
        pairs = [(nums[i], nums[i + 1]) for i in range(0, len(nums) - 1, 2) if nums[i + 1] > 1]
    if len(pairs) < 8:
        return
    x = S._crt([r for r, m in pairs], [m for r, m in pairs])
    if x is None:
        return
    n = max(1, (x.bit_length() + 7) // 8)
    out = x.to_bytes(n, "big")
    yield out, "CRT combined", {"moduli": len(pairs)}, max(assess(out)[0], flag_plausibility(out.decode("latin-1")))


def _radix_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "").strip()
    toks = t.split()
    return .6 if 4 <= len(toks) <= 2000 and all(re.fullmatch(r"[0-9a-zA-Z]+", x) for x in toks) else 0.0


@solver("radix-ascii", _radix_prior)
def solve_radix(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    toks = text.split()
    if len(toks) < 4:
        return
    emitted = set()
    for base in range(2, 37):
        try:
            vals = [int(t, base) for t in toks]
        except ValueError:
            continue
        if not all(1 <= v <= 255 for v in vals):
            continue
        out = bytes(vals)
        if out in emitted:
            continue
        emitted.add(out)
        score, _ = assess(out)
        yield out, "radix-ascii", {"base": base}, score


# ------------------------------------------------------- reverse transforms
def _reverse_prior(fp):
    return .5 if fp["charset"] == "ascii-text" and fp["length"] >= 10 else 0.0


@solver("reverse-words", _reverse_prior)
def solve_reverse_words(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    words = re.split(r"(\s+)", text)
    words.reverse()
    out = "".join(words)
    if out != text:
        score, _ = assess(out)
        yield out, "reverse-words", {}, score


@solver("reverse-each-word", _reverse_prior)
def solve_reverse_each(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    out = re.sub(r"[A-Za-z]+", lambda m: m.group(0)[::-1], text)
    if out != text:
        score, _ = assess(out)
        yield out, "reverse-each-word", {}, score


# --------------------------------------------------- DSA nonce reuse (ints)
def _dsa_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    return .9 if re.search(r"\bq\s*[:=]", t) and re.search(r"\b(?:s1|s2)\s*[:=]", t) else 0.0


@solver("dsa-nonce-reuse", _dsa_prior)
def solve_dsa_reuse(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v = {}
    for k, val in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*(\d+)", text):
        v.setdefault(k.lower(), int(val))
    q = v.get("q")
    r = v.get("r")
    s1, s2 = v.get("s1"), v.get("s2")
    h1, h2 = v.get("h1"), v.get("h2")
    if not (q and r and s1 is not None and s2 is not None and h1 is not None and h2 is not None):
        return
    if s1 == s2 or q < 2:
        return
    try:
        k = (h1 - h2) * pow(s1 - s2, -1, q) % q
        d = (s1 * k - h1) * pow(r, -1, q) % q
    except (ValueError, ZeroDivisionError):
        return
    yield f"d={d} k={k}".encode(), "Cracked DSA nonce reuse", {"q": q}, .98


# --------------------------------------------------------- RSA shared-prime
def _shared_prime_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    need = ("n1", "n2", "c1", "c2")
    return .9 if all(re.search(r"\b%s\s*[:=]" % x, t) for x in need) else 0.0


@solver("rsa-shared-prime", _shared_prime_prior)
def solve_shared_prime(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v = {}
    for k, val in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*(\d+)", text):
        v.setdefault(k.lower(), int(val))
    n1, n2 = v.get("n1"), v.get("n2")
    c1, c2 = v.get("c1"), v.get("c2")
    e = v.get("e", 65537)
    if not (n1 and n2 and c1 is not None and c2 is not None):
        return
    p = math.gcd(n1, n2)
    if p <= 1 or p == n1 or p == n2:
        return
    for n, c in ((n1, c1), (n2, c2)):
        q = n // p
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        m = pow(c, pow(e, -1, phi), n)
        yield S._int_plain(m), "RSA shared-prime", {"p": p}, .98


# --------------------------------------------------------------- RSA dp/dq
def _dpdq_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    need = ("dp", "dq", "p", "q", "c")
    return .9 if all(re.search(r"\b%s\s*[:=]" % x, t) for x in need) else 0.0


@solver("rsa-dp-dq-leak", _dpdq_prior)
def solve_dpdq(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v = {}
    for k, val in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*(\d+)", text):
        v.setdefault(k.lower(), int(val))
    p, q = v.get("p"), v.get("q")
    dp, dq = v.get("dp"), v.get("dq")
    c = v.get("c")
    if not (p and q and dp is not None and dq is not None and c is not None):
        return
    if not (_is_prime(p) and _is_prime(q)):
        return
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    m = S._crt([m1, m2], [p, q])
    if m is not None:
        yield S._int_plain(m), "RSA dp/dq", {"dp": dp, "dq": dq}, .98


# ------------------------------------------------------------ Franklin-Reiter
def _fr_pmod(a, b, N):
    a = a[:]
    try:
        inv = pow(b[-1], -1, N)
    except ValueError:
        return None
    while len(a) >= len(b):
        q = a[-1] * inv % N
        s = len(a) - len(b)
        for i, x in enumerate(b):
            a[s + i] = (a[s + i] - q * x) % N
        a.pop()
    return a


def _fr_gcd(f, g, N):
    while g and g != [0]:
        r = _fr_pmod(f, g, N)
        if r is None:
            return None
        f, g = g, r
    return f


def _fr_recover(c1, c2, d, N, e):
    """Two messages m and m+d encrypted with exponent e under modulus N."""
    f1 = [(-c1) % N] + [0] * (e - 1) + [1]
    f2 = [(-c2) % N] + [0] * (e - 1) + [1]
    # (x + d)^e - c2 mod N
    binom = [math.comb(e, k) * pow(d, e - k, N) % N for k in range(e + 1)]
    f2 = [(binom[k] if k < e else 1) % N for k in range(e + 1)]
    f2[0] = (f2[0] - c2) % N
    g = _fr_gcd(f1, f2, N)
    if g is None or len(g) > 2:
        return None
    if len(g) == 2:
        a, b = g[1], g[0]
        try:
            return (-b) * pow(a, -1, N) % N
        except ValueError:
            return None
    return None


def _fr_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    nums = re.findall(r"\d+", t)
    if len(nums) >= 4 and (re.search(r"\bc1\s*[:=]", t) or len(nums) == 4):
        return .7
    return 0.0


def _fr_recover_general(c1, c2, a, b, N, e):
    """Franklin-Reiter for related messages m2 = a*m1 + b (mod N), e=3.
    A closed-form elimination: subtract a^3*(m^3 - c1) from (a*m+b)^3 - c2
    to get a quadratic Q in m; then multiply Q by m and substitute m^3=c1
    for a second quadratic; cancelling m^2 between them yields a linear
    equation in m. Returns m (int) or None."""
    if e != 3 or b % N == 0:
        return None
    a %= N
    b %= N
    u = (3 * a * a * b) % N
    v = (3 * a * b * b) % N
    w = (b * b * b - c2 + a * a * a * c1) % N
    # v*Q - u*(m*Q):
    # (v^2 - u*w)*m + (v*w - u^2*c1) == 0
    A = (v * v - u * w) % N
    B = (v * w - u * u * c1) % N
    try:
        m = (-B * pow(A, -1, N)) % N
    except ValueError:
        return None
    # verify both equations hold
    if pow(m, 3, N) != c1 % N:
        return None
    if pow((a * m + b) % N, 3, N) != c2 % N:
        return None
    return m


@solver("franklin-reiter", _fr_prior)
def solve_franklin_reiter(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v = {}
    for k, val in re.findall(
            r"\b([A-Za-z_]\w*)\s*[:=]?\s*(0x[0-9a-f]+|\d+)", text):
        val = int(val, 16) if val.lower().startswith("0x") else int(val)
        v.setdefault(k.lower(), val)
    c1 = v.get("c1")
    c2 = v.get("c2")
    a = v.get("a", v.get("A", 1))
    b = v.get("b", v.get("B", v.get("diff", v.get("d", 0))))
    N = v.get("n", v.get("modulus", v.get("N")))
    e = v.get("e", 3)
    if c1 is None or c2 is None or N is None:
        nums = [int(x) for x in re.findall(r"\d+", text)]
        if len(nums) == 4:
            c1, c2, a, N = nums
            b = 0
        else:
            return
    if not (N and N > 1 and 2 <= e <= 7 and 0 <= b < N
            and 1 <= a < N):
        return
    # Guard against accidental label matches on ordinary text: a real
    # Franklin-Reiter modulus is at least 128 bits and both ciphertexts must
    # be proper residues mod N.
    if N.bit_length() < 128 or c1 >= N or c2 >= N:
        return
    if e == 3 and b % N != 0:
        # m2 = a*m + b: subtract a^3*(m^3-c1) from (a*m+b)^3-c2 -> quadratic Q;
        # multiply Q by m and substitute m^3=c1 for a second quadratic; the
        # linear combination cancelling m^2 gives m directly.
        u = (3 * a * a * b) % N
        v = (3 * a * b * b) % N
        w = (b * b * b - c2 + a * a * a * c1) % N
        A = (v * v - u * w) % N
        B = (v * w - u * u * c1) % N
        try:
            m = (-B * pow(A, -1, N)) % N
        except ValueError:
            m = None
        if m is not None and (pow(m, 3, N) != c1 % N
                              or pow((a * m + b) % N, 3, N) != c2 % N):
            m = None
    else:
        m = _fr_recover(c1, c2, b if b else a, N, e)
    if m is not None:
        yield S._int_plain(m), "RSA Franklin-Reiter", {"e": e, "a": a, "b": b}, .98


# ------------------------------------------------------------- LCG / MT19937
def _nums_prior(fp, minimum):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    nums = re.findall(r"\d+", t)
    return .75 if len(nums) >= minimum else 0.0


def _lcg_recover(outputs):
    if len(outputs) < 6:
        return None
    g = 0
    for i in range(len(outputs) - 2):
        t0 = outputs[i + 1] - outputs[i]
        t1 = outputs[i + 2] - outputs[i + 1]
        t2 = outputs[i + 3] - outputs[i + 2] if i + 3 < len(outputs) else t1
        v = abs(t2 * t0 - t1 * t1)
        g = math.gcd(g, v)
    if g <= 1:
        return None
    # True modulus is g * 2^k (differences often share power-of-two factors).
    for shift in range(64):
        m = g << shift
        if m <= 1:
            continue
        for i in range(1, len(outputs) - 1):
            try:
                a = (outputs[i + 1] - outputs[i]) * pow(outputs[i] - outputs[i - 1], -1, m) % m
            except ValueError:
                continue
            c = (outputs[i + 1] - a * outputs[i]) % m
            if all((a * outputs[j] + c) % m == outputs[j + 1] for j in range(len(outputs) - 1)):
                return a, c, m
    return None


@solver("lcg-recover", lambda fp: _nums_prior(fp, 6))
def solve_lcg(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    nums = [int(x) for x in re.findall(r"\d+", text)]
    if len(nums) < 6:
        return
    r = _lcg_recover(nums)
    if r:
        a, c, m = r
        nxt = (a * nums[-1] + c) % m
        yield f"a={a} c={c} m={m} next={nxt}".encode(), "Cracked LCG", {"m": m}, .98


_MT_N = 624
_MT_M = 397
_MT_MATRIX = 0x9908b0df
_MT_UPPER = 0x80000000
_MT_LOWER = 0x7fffffff


def _unshift_right_xor(y, shift):
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ (x >> shift)
    return x


def _unshift_left_xor(y, shift, mask):
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ ((x << shift) & mask)
    return x


def _mt_untemper(y):
    y = _unshift_right_xor(y, 18)
    y = _unshift_left_xor(y, 15, 0xefc60000)
    y = _unshift_left_xor(y, 7, 0x9d2c5680)
    y = _unshift_right_xor(y, 11)
    return y


def _mt_next(state):
    idx = state[624]
    if idx >= 624:
        for i in range(624):
            y = (state[i] & _MT_UPPER) | (state[(i + 1) % 624] & _MT_LOWER)
            state[i] = state[(i + _MT_M) % 624] ^ (y >> 1)
            if y & 1:
                state[i] ^= _MT_MATRIX
        idx = 0
    y = state[idx]
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    state[624] = idx + 1
    return y


def _bsgs_int(g, h, order, p):
    s = math.isqrt(order) + 1
    table = {}
    cur = 1
    for j in range(s):
        table[cur] = j
        cur = cur * g % p
    step = pow(g, s, p)
    inv_step = pow(step, -1, p)
    gamma = h % p
    for i in range(s + 1):
        if gamma in table:
            k = table[gamma] + i * s
            if pow(g, k, p) == h % p:
                return k
        gamma = gamma * inv_step % p
    return None


def _dlp_pm1(g, h, p, ctx):
    """Solve h = g^x mod p when p-1 is smooth (Pohlig-Hellman + BSGS)."""
    n = p - 1
    rem, mod = [], []
    for q, e in _trial_fac(n, 2_000_000):
        ne = q ** e
        if ne > 2 ** 22:
            return None
        gi = pow(g, n // ne, p)
        hi = pow(h, n // ne, p)
        xi = _bsgs_int(gi, hi, ne, p)
        if xi is None:
            return None
        rem.append(xi)
        mod.append(ne)
    M = math.prod(mod)
    x = 0
    for r, m in zip(rem, mod):
        Mi = M // m
        x += r * Mi * pow(Mi, -1, m)
    x %= M
    if pow(g, x, p) == h % p:
        return x
    # x may differ by a multiple of the true order; p-1 small enough to scan.
    for delta in range(0, n, M):
        if pow(g, (x + delta) % n, p) == h % p:
            return (x + delta) % n
    return None


def _trial_fac(n, limit):
    fac = []
    d = 2
    cnt = 0
    while d * d <= n and d <= limit and cnt < 40:
        if n % d == 0:
            e = 0
            while n % d == 0:
                n //= d
                e += 1
            fac.append((d, e))
            cnt += 1
        d += 1 if d == 2 else 2
    if n > 1:
        fac.append((n, 1))
    return fac


def _dh_dlp_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    need = ("g", "p", "A", "B")
    return .85 if all(re.search(r"\b%s\s*[:=]" % x, t) for x in need) else 0.0


@solver("dh-dlp", _dh_dlp_prior)
def solve_dh_dlp(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v = {}
    for k, val in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*(\d+)", text):
        v.setdefault(k.lower(), int(val))
    g = v.get("g")
    p = v.get("p")
    A = v.get("A")
    B = v.get("B")
    if not (g and p and A is not None and B is not None and p > 2):
        return
    a = _dlp_pm1(g, A, p, ctx)
    if a is None:
        return
    if pow(g, a, p) != A % p:
        return
    shared = pow(B, a, p)
    out = shared.to_bytes(max(1, (shared.bit_length() + 7) // 8), "big")
    yield out, "Cracked DH-DLP", {"a": a, "p_bits": p.bit_length()}, .98


@solver("mt19937-predict", lambda fp: _nums_prior(fp, 624))
def solve_mt(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    nums = [int(x) for x in re.findall(r"\d+", text)]
    if len(nums) < 624:
        return
    state = [_mt_untemper(y) & 0xffffffff for y in nums[:624]] + [624]
    nxt = [_mt_next(state) for _ in range(4)]
    expect = nums[624:628] if len(nums) >= 628 else None
    if expect and nxt == expect:
        yield f"next={nxt[0]},{nxt[1]},{nxt[2]},{nxt[3]}".encode(), "Cracked MT19937", {"predictions": 4}, .98


# ------------------------------------------------------------- RC4 / AES glue
def _rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def _key_prior(fp):
    if fp.get("charset") == "ascii-text" and re.search(r"\bkey\s*[:=]", fp.get("_text", "")):
        return .7
    if fp["length"] >= 8 and re.search(r"\bkey\s*[:=]", fp.get("_text", "")):
        return .7
    return 0.0


@solver("rc4-key", _key_prior)
def solve_rc4(data, ctx):
    try:
        text = data.decode("latin-1")
    except Exception:
        return
    m = re.search(r"\bkey\s*[:=]\s*(\S+)", text)
    if not m:
        return
    key = m.group(1)
    if key.startswith(("0x", "0X")):
        try:
            key = bytes.fromhex(key[2:])
        except ValueError:
            return
    else:
        key = key.encode()
    lines = [ln for ln in text.splitlines() if not re.match(r"\s*key\s*[:=]", ln)]
    blob = "".join(lines)
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        raw = data
    for cand in (raw, data):
        out = _rc4(key, cand)
        if out and len(out) >= 4:
            score, _ = assess(out)
            yield out, "RC4 key", {"key_len": len(key)}, score


def _ecb_prior(fp):
    return .6 if fp["length"] >= 32 and "repeated 16-byte blocks" in fp.get("magic", []) else 0.0


@solver("ecb-repeated-blocks", _ecb_prior)
def solve_ecb_detect(data, ctx):
    if ctx.depth > 0:
        return
    blocks = [data[i:i + 16] for i in range(0, len(data) - 15, 16)]
    dup = [b for b in set(blocks) if blocks.count(b) > 1]
    if dup:
        ctx.findings.append(f"ECB: {len(dup)} repeated 16-byte ciphertext block(s) "
                            f"(first: {dup[0].hex()[:32]}...); block cipher ECB mode suspected.")
        yield b"", "ECB repeated-block finding", {}, .6


try:
    from Crypto.Cipher import AES as _AES
except Exception:
    _AES = None
try:
    from cryptography.fernet import Fernet as _Fernet
except Exception:
    _Fernet = None


@solver("aes-key", _key_prior)
def solve_aes(data, ctx):
    if _AES is None:
        return
    try:
        text = data.decode("latin-1")
    except Exception:
        return
    kv = {}
    for k, val in re.findall(r"\b(key|iv|mode)\s*[:=]\s*(\S+)", text, re.I):
        kv.setdefault(k.lower(), val)
    if "key" not in kv:
        return
    try:
        key = bytes.fromhex(kv["key"].replace("0x", ""))
    except ValueError:
        key = kv["key"].encode()
    iv = None
    if "iv" in kv:
        try:
            iv = bytes.fromhex(kv["iv"].replace("0x", ""))
        except ValueError:
            return
    mode = kv.get("mode", "ecb").lower()
    lines = [ln for ln in text.splitlines() if not re.match(r"\s*(key|iv|mode)\s*[:=]", ln)]
    blob = "".join(lines).strip()
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return
    try:
        if mode in ("ecb", "cbc", "ctr", "cfb", "ofb"):
            if mode == "ecb":
                c = _AES.new(key, _AES.MODE_ECB)
            elif mode == "cbc":
                c = _AES.new(key, _AES.MODE_CBC, iv)
            elif mode == "ctr":
                from Crypto.Util import Counter
                c = _AES.new(key, _AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv, "big")))
            elif mode == "cfb":
                c = _AES.new(key, _AES.MODE_CFB, iv)
            else:
                c = _AES.new(key, _AES.MODE_OFB, iv)
            out = c.decrypt(raw)
            score, _ = assess(out)
            yield out, f"AES-{mode.upper()}", {"key_len": len(key)}, score
    except Exception:
        return


@solver("fernet-key", _key_prior)
def solve_fernet(data, ctx):
    if _Fernet is None:
        return
    try:
        text = data.decode("latin-1")
    except Exception:
        return
    m = re.search(r"\bkey\s*[:=]\s*(\S+)", text)
    if not m:
        return
    lines = [ln for ln in text.splitlines() if not re.match(r"\s*key\s*[:=]", ln)]
    token = "".join(lines).strip()
    try:
        f = _Fernet(m.group(1).encode())
        out = f.decrypt(token.encode())
        score, _ = assess(out)
        yield out, "Fernet", {"key_len": len(m.group(1))}, score
    except Exception:
        return


# ------------------------------------------- short repeating-key XOR (joint)
def _xor_score(out):
    n = len(out)
    if not n:
        return -9.0
    pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / n
    an = sum(48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 for b in out) / n
    if pr < .95 or an < .65:
        return -3.0 + pr + an
    txt = out.decode("latin-1")
    return 0.3 * english_confidence(txt) + 0.7 * flag_plausibility(txt)


def _xor_short_prior(fp):
    if fp["length"] < 8 or fp["length"] > 400:
        return 0.0
    t = fp.get("_text", "")
    if fp["charset"] == "ascii-text" and re.fullmatch(r"[0-9a-fA-F\s]+", t):
        return .5
    if fp["charset"] in ("binary", "mixed"):
        return .5
    return 0.0


@solver("xor-short", _xor_short_prior)
def solve_xor_short(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    raw = None
    if re.fullmatch(r"[0-9a-fA-F\s]+", text.strip()):
        try:
            raw = bytes.fromhex(re.sub(r"\s", "", text))
        except ValueError:
            raw = None
    if raw is None:
        raw = data
    if not raw or len(raw) < 6:
        return
    _LETTER_Q = [.08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094,
                 .06966, .00153, .00772, .04025, .02406, .06749, .07507, .01929,
                 .00095, .05987, .06327, .09056, .02758, .00978, .02360, .00150,
                 .01974, .00074]

    def _byte_like(v):
        if 65 <= v <= 90 or 97 <= v <= 122:
            return _LETTER_Q[(v & 0x1f) - 1]
        if 48 <= v <= 57 or v in (95, 123, 125, 32, 45):
            return .05
        return 0.0

    best = None
    for L in range(1, 9):
        if ctx.expired():
            break
        if L > len(raw):
            break
        key = bytearray(L)
        for j in range(L):
            col = raw[j::L]
            best_v, best_s = 0, -1.0
            for v in range(256):
                s = sum(_byte_like(b ^ v) for b in col)
                if s > best_s:
                    best_v, best_s = v, s
            key[j] = best_v
        out = bytes(b ^ key[i % L] for i, b in enumerate(raw))
        sc = _xor_score(out)
        if best is None or sc > best[0]:
            best = (sc, out, bytes(key), L)
    if best and best[0] >= .55:
        sc, out, key, L = best
        yield out, "Cracked short XOR", {"key": key.hex(), "key_len": L, "_statistical": True}, min(.95, .6 + .35 * sc)


# ------------------------------------------------------------ hash cracking
_BUILTIN_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345", "qwerty", "abc123",
    "letmein", "admin", "monkey", "dragon", "111111", "baseball", "iloveyou",
    "trustno1", "sunshine", "master", "welcome", "shadow", "ashley", "michael",
    "football", "jordan", "harley", "ranger", "hunter", "fuckyou", "whatever",
    "passw0rd", "p@ssw0rd", "ctf", "flag", "academy", "autocrypt", "secret",
]


def _md4(data):
    # pure-Python MD4 (RFC 1320), used for NTLM
    import struct as _st
    def lrot(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    msg = bytearray(data)
    ml = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += ml.to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        X = list(_st.unpack("<16I", msg[off:off + 64]))
        A, B, C, D = a0, b0, c0, d0
        def f(x, y, z): return (x & y) | (~x & z)
        def g(x, y, z): return (x & y) | (x & z) | (y & z)
        def h(x, y, z): return x ^ y ^ z
        for i in range(16):
            k = i
            s = (3, 7, 11, 19)[i % 4]
            A = lrot((A + f(B, C, D) + X[k]) & 0xffffffff, s)
            A, B, C, D = D, A, B, C
        for i in range(16):
            k = (i % 4) * 4 + i // 4
            s = (3, 5, 9, 13)[i % 4]
            A = lrot((A + g(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s)
            A, B, C, D = D, A, B, C
        for i in range(16):
            k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i]
            s = (3, 9, 11, 15)[i % 4]
            A = lrot((A + h(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            A, B, C, D = D, A, B, C
        a0 = (a0 + A) & 0xffffffff
        b0 = (b0 + B) & 0xffffffff
        c0 = (c0 + C) & 0xffffffff
        d0 = (d0 + D) & 0xffffffff
    return _st.pack("<4I", a0, b0, c0, d0)


_HASH_FUNCS = {
    "md5": lambda b: hashlib.md5(b).hexdigest(),
    "sha1": lambda b: hashlib.sha1(b).hexdigest(),
    "sha224": lambda b: hashlib.sha224(b).hexdigest(),
    "sha256": lambda b: hashlib.sha256(b).hexdigest(),
    "sha384": lambda b: hashlib.sha384(b).hexdigest(),
    "sha512": lambda b: hashlib.sha512(b).hexdigest(),
    "ntlm": lambda b: _md4(b).hex(),
}


def _hash_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "").strip()
    for line in t.splitlines():
        m = re.match(
            r"^\s*(?:(?:md5|sha1|sha224|sha256|sha384|sha512|ntlm|hash)"
            r"\s*[:=]\s*)?([0-9a-fA-F]+)", line)
        if not m:
            continue
        h = m.group(1)
        if len(h) in (32, 40, 56, 64, 96, 128) and re.fullmatch(
                r"[0-9a-fA-F]+", h):
            return .98
    return 0.0


def _hash_candidates(ctx):
    if ctx.wordlist:
        for w in ctx.wordlist:
            yield w
    for w in _BUILTIN_PASSWORDS:
        yield w.encode()
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    for a in alpha:
        yield a.encode()
    for a in alpha:
        for b in alpha:
            yield (a + b).encode()
    for a in alpha:
        for b in alpha:
            for c in alpha:
                yield (a + b + c).encode()
    for a in alpha:
        for b in alpha:
            for c in alpha:
                for d in alpha:
                    yield (a + b + c + d).encode()
    for i in range(1_000_000):
        yield str(i).encode()


@solver("hash-crack", _hash_prior)
def solve_hash_crack(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    for line in text.splitlines():
        if ctx.expired():
            return
        line = line.strip()
        if not line:
            continue
        # Accept bare hex, or labeled forms: "hash = <hex>",
        # "md5 = <hex>", "sha256: <hex>", with optional ":salt" suffix.
        m = re.match(
            r"^\s*(?:(?:md5|sha1|sha224|sha256|sha384|sha512|ntlm|hash)"
            r"\s*[:=]\s*)?([0-9a-fA-F]+)(?::(.+))?\s*$", line)
        if not m:
            continue
        h = m.group(1).lower()
        salt = (m.group(2) or "").strip()
        # "<hash>:<longhex>" is a hash+ciphertext line, not a salted hash.
        if salt and re.fullmatch(r"[0-9a-fA-F]{8,}", salt):
            _ct_from_salt = salt
            salt = ""
        else:
            _ct_from_salt = None
        name = None
        for n, fn in _HASH_FUNCS.items():
            if len(h) == (32 if n == "md5" else 40 if n == "sha1" else 56 if n == "sha224" else 64 if n in ("sha256", "ntlm") else 96 if n == "sha384" else 128) and re.fullmatch(r"[0-9a-f]+", h):
                name = n
                break
        if not name:
            continue
        fn = _HASH_FUNCS[name]
        found = None
        for cand in _hash_candidates(ctx):
            if ctx.expired():
                break
            if salt:
                if fn(cand + salt.encode()) == h or fn(salt.encode() + cand) == h:
                    found = cand
                    break
            else:
                if fn(cand) == h:
                    found = cand
                    break
        if found is not None:
            # Pair with an XOR ciphertext in the same text, if present:
            # key = digest of the cracked password, cycled over the bytes.
            try:
                _hl = __import__("hashlib")
                # typical challenge style: XOR key = hexdigest ASCII bytes
                digest_bytes = getattr(_hl, name)(found).hexdigest().encode()
            except Exception:
                digest_bytes = None
            if digest_bytes:
                _extra = [salt] if _ct_from_salt is not None else []
                for ln in _extra + text.splitlines():
                    for _tok in re.findall(r"[0-9a-fA-F]{8,}", ln):
                        if _tok.lower() == h or len(_tok) % 2:
                            continue
                        try:
                            raw = bytes.fromhex(_tok)
                            out = bytes(raw[i] ^ digest_bytes[i % len(digest_bytes)]
                                       for i in range(len(raw)))
                            if out:
                                yield out, f"Cracked hash-xor ({name})", {
                                    "salt": salt,
                                    "password": found.decode(errors="replace"),
                                    "_statistical": True}, .98
                        except ValueError:
                            continue
                        break
                    else:
                        continue
                    break
            yield found, f"Cracked hash ({name})", {"salt": salt, "_statistical": True}, .98
            return


# --------------------------------------------------- Vigenere dict / Beaufort / Porta
_VIG_DICT = ["KEY", "LEMON", "SECRET", "CRYPTO", "ORANGE", "CIPHER", "VICTOR",
             "MOSCOW", "FORTUNA", "PASSWORD", "KEYWORD", "PRIME", "BLUE", "SUN"]


def _vigenere_decrypt(text, key):
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[j % len(key)]) - ord("A")
            out.append(chr(base + (ord(ch) - base - k) % 26))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def _vigenere_dict_prior(fp):
    return .55 if fp["charset"] == "ascii-text" and fp["length"] >= 12 else 0.0


@solver("vigenere-dictionary", _vigenere_dict_prior)
def solve_vigenere_dict(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    letters = "".join(ch for ch in text if ch.isalpha()).upper()
    if len(letters) < 6:
        return
    keys = list(_VIG_DICT)
    if ctx.wordlist:
        keys += [w.decode("ascii", "ignore").upper() for w in ctx.wordlist[:2000] if len(w) <= 20]
    seen = set()
    ranked = []
    for key in dict.fromkeys(keys):
        if not key or len(key) > 24:
            continue
        if ctx.expired():
            return
        dec = _vigenere_decrypt(letters, key)
        # Weave the decrypted letters back into the original text so digits,
        # braces, underscores and original case are preserved.
        it = iter(dec)
        out = "".join(next(it) if ch.isalpha() else ch for ch in text)
        if out in seen:
            continue
        seen.add(out)
        ranked.append((english_confidence(out), out, key))
    ranked.sort(key=lambda t: (-t[0], len(t[2])))
    for i, (ec, out, key) in enumerate(ranked[:12]):
        params = {"key": key}
        if i == 0 and ec >= 0.5:
            params["_statistical"] = True
            yield out, "vigenere-dictionary", params, min(0.95, 0.55 + 0.35 * ec)
        else:
            yield out, "vigenere-dictionary", params, max(assess(out)[0], flag_plausibility(out))


_BEAUFORT_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_PORTA_ROWS = {}
_FIRST13 = "NOPQRSTUVWXYZ"
_SECOND13 = "ABCDEFGHIJKLM"
for _s in range(13):
    _PORTA_ROWS[_BEAUFORT_ALPH[_s * 2:_s * 2 + 2]] = (
        _FIRST13[_s:] + _FIRST13[:_s] + _SECOND13[13 - _s:] + _SECOND13[:13 - _s])


def _beaufort_decrypt(text, key):
    out = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[i % len(key)]) - ord("A")
            out.append(chr(base + (k - (ord(ch) - base)) % 26))
        else:
            out.append(ch)
    return "".join(out)


def _porta_decrypt(text, key):
    out = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[i % len(key)].upper()) - ord("A")
            pair = _BEAUFORT_ALPH[(k // 2) * 2:(k // 2) * 2 + 2]
            row = _PORTA_ROWS.get(pair)
            if row is None:
                return None
            idx = row.find(ch.upper())
            if idx < 0:
                return None
            out.append(chr(base + idx))
        else:
            out.append(ch)
    return "".join(out)


def _classical_key_prior(fp):
    return .5 if fp["charset"] == "ascii-text" and fp["length"] >= 20 else 0.0


def _column_key_recover(letters, length, mode):
    key = []
    for j in range(length):
        col = letters[j::length]
        best, best_s = None, -1.0
        for d in range(26):
            if mode == "beaufort":
                s = sum(_EN_FREQ26[(d - (ord(c) - 65)) % 26] for c in col)
            else:
                s = sum(_EN_FREQ26[(ord(c) - 65 + d) % 26] for c in col)
            if s > best_s:
                best, best_s = d, s
        key.append(_BEAUFORT_ALPH[best])
    return "".join(key)


@solver("beaufort", _classical_key_prior)
def solve_beaufort(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    letters = "".join(ch for ch in text if ch.isalpha()).upper()
    if len(letters) < 15:
        return
    variants = []
    for length in range(1, min(20, len(letters) // 2) + 1):
        if ctx.expired():
            return
        key = _column_key_recover(letters, length, "beaufort")
        out = _beaufort_decrypt(letters, key)
        variants.append((out, key))
    for k in _VIG_DICT:
        if ctx.expired():
            return
        out = _beaufort_decrypt(letters, k)
        variants.append((out, k))
    scored = [(quadgram_score(o), o, k) for o, k in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, o, k in scored:
        if o not in seen:
            seen.add(o)
            uniq.append((q, o, k))
    # Prefer clearly-English decrypts; penalize overfit longer keys.
    uniq.sort(key=lambda t: (-english_confidence(t[1]), len(t[2])))
    boost = len(uniq) >= 2 and english_confidence(uniq[0][1]) >= .5 \
        and english_confidence(uniq[0][1]) >= english_confidence(uniq[1][1])
    for i, (_, o, k) in enumerate(uniq[:3]):
        params = {"key": k}
        if i == 0 and boost:
            params["_statistical"] = True
            yield o, "beaufort", params, min(0.95, 0.55 + 0.35 * english_confidence(o))
        else:
            yield o, "beaufort", params, max(assess(o)[0], flag_plausibility(o))


@solver("porta", _classical_key_prior)
def solve_porta(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    letters = "".join(ch for ch in text if ch.isalpha()).upper()
    if len(letters) < 15:
        return
    variants = []
    for length in range(1, min(20, len(letters) // 2) + 1):
        if ctx.expired():
            return
        key = _column_key_recover(letters, length, "porta")
        out = _porta_decrypt(letters, key)
        if out:
            variants.append((out, key))
    for k in _VIG_DICT:
        if ctx.expired():
            return
        out = _porta_decrypt(letters, k)
        if out:
            variants.append((out, k))
    scored = [(quadgram_score(o), o, k) for o, k in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, o, k in scored:
        if o not in seen:
            seen.add(o)
            uniq.append((q, o, k))
    uniq.sort(key=lambda t: (-english_confidence(t[1]), len(t[2])))
    boost = len(uniq) >= 2 and english_confidence(uniq[0][1]) >= .5 \
        and english_confidence(uniq[0][1]) >= english_confidence(uniq[1][1])
    for i, (_, o, k) in enumerate(uniq[:3]):
        params = {"key": k}
        if i == 0 and boost:
            params["_statistical"] = True
            yield o, "porta", params, min(0.95, 0.55 + 0.35 * english_confidence(o))
        else:
            yield o, "porta", params, max(assess(o)[0], flag_plausibility(o))


# ----------------------------------------------------------- Hill 3x3 with crib
def _hill3_decrypt(letters, key9, mod=26):
    inv = None
    det = (key9[0] * (key9[4] * key9[8] - key9[5] * key9[7])
           - key9[1] * (key9[3] * key9[8] - key9[5] * key9[6])
           + key9[2] * (key9[3] * key9[7] - key9[4] * key9[6])) % mod
    det = det % mod
    g = math.gcd(det, mod)
    if g != 1:
        return None
    dinv = pow(det, -1, mod)
    inv = [0] * 9
    inv[0] = (key9[4] * key9[8] - key9[5] * key9[7]) * dinv % mod
    inv[1] = (key9[2] * key9[7] - key9[1] * key9[8]) * dinv % mod
    inv[2] = (key9[1] * key9[5] - key9[2] * key9[4]) * dinv % mod
    inv[3] = (key9[5] * key9[6] - key9[3] * key9[8]) * dinv % mod
    inv[4] = (key9[0] * key9[8] - key9[2] * key9[6]) * dinv % mod
    inv[5] = (key9[2] * key9[3] - key9[0] * key9[5]) * dinv % mod
    inv[6] = (key9[3] * key9[7] - key9[4] * key9[6]) * dinv % mod
    inv[7] = (key9[1] * key9[6] - key9[0] * key9[7]) * dinv % mod
    inv[8] = (key9[0] * key9[4] - key9[1] * key9[3]) * dinv % mod
    out = []
    for i in range(0, len(letters) - 2, 3):
        v = [ord(c) - 65 for c in letters[i:i + 3]]
        for r in range(3):
            s = sum(inv[r * 3 + c] * v[c] for c in range(3)) % mod
            out.append(chr(65 + s))
    return "".join(out)


def _hill3_crib_prior(fp):
    return .8 if fp["charset"] == "ascii-text" and fp["length"] >= 30 else 0.0


@solver("hill3-crib", _hill3_crib_prior)
def solve_hill3(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    letters = "".join(ch for ch in text if ch.isalpha()).upper()
    crib = "".join(ch for ch in (ctx.known_plaintext or "").upper() if ch.isalpha())
    if len(letters) < 12 or len(crib) < 9:
        return
    candidates = []
    for rot in range(3):   # try every 3-letter block phase
        if ctx.expired():
            break
        rotated = letters[rot:] + letters[:rot]
        for win in range(0, len(crib) - 8, 3):
            if ctx.expired():
                break
            crib9 = crib[win:win + 9]
            pt9 = [ord(c) - 65 for c in crib9]
            triples = [[pt9[i], pt9[i + 1], pt9[i + 2]] for i in range(0, 9, 3)]
            P = [[triples[0][r], triples[1][r], triples[2][r]] for r in range(3)]
            det = (P[0][0] * (P[1][1] * P[2][2] - P[1][2] * P[2][1])
                   - P[0][1] * (P[1][0] * P[2][2] - P[1][2] * P[2][0])
                   + P[0][2] * (P[1][0] * P[2][1] - P[1][1] * P[2][0])) % 26
            if math.gcd(det, 26) != 1:
                continue
            dinv = pow(det, -1, 26)
            Pinv = [0] * 9
            Pinv[0] = (P[1][1] * P[2][2] - P[1][2] * P[2][1]) * dinv % 26
            Pinv[1] = (P[0][2] * P[2][1] - P[0][1] * P[2][2]) * dinv % 26
            Pinv[2] = (P[0][1] * P[1][2] - P[0][2] * P[1][1]) * dinv % 26
            Pinv[3] = (P[1][2] * P[2][0] - P[1][0] * P[2][2]) * dinv % 26
            Pinv[4] = (P[0][0] * P[2][2] - P[0][2] * P[2][0]) * dinv % 26
            Pinv[5] = (P[0][2] * P[1][0] - P[0][0] * P[1][2]) * dinv % 26
            Pinv[6] = (P[1][0] * P[2][1] - P[1][1] * P[2][0]) * dinv % 26
            Pinv[7] = (P[0][1] * P[2][0] - P[0][0] * P[2][1]) * dinv % 26
            Pinv[8] = (P[0][0] * P[1][1] - P[0][1] * P[1][0]) * dinv % 26
            for start in range(0, len(rotated) - 2, 3):
                if ctx.expired():
                    break
                ct9 = [ord(c) - 65 for c in rotated[start:start + 9]]
                if len(ct9) < 9:
                    break
                ctriples = [[ct9[i], ct9[i + 1], ct9[i + 2]] for i in range(0, 9, 3)]
                C = [[ctriples[0][r], ctriples[1][r], ctriples[2][r]] for r in range(3)]
                K = [0] * 9
                for r in range(3):
                    for c in range(3):
                        K[r * 3 + c] = sum(C[r][k] * Pinv[k * 3 + c] for k in range(3)) % 26
                out = _hill3_decrypt(rotated, K)
                if out is not None:
                    out = out[-rot:] + out[:-rot] if rot else out
                    candidates.append((out, rot, start))
    # Yield the crib-matching recovery first if any; otherwise the most
    # English-looking candidate.
    seen = set()
    candidates.sort(key=lambda t: -english_confidence(t[0]))
    for out, rot, start in candidates:
        if out in seen:
            continue
        seen.add(out)
        if crib[:9] in out:
            yield out, "hill3-crib", {"rot": rot, "start": start, "_statistical": True}, .98
            return
    for out, rot, start in candidates[:3]:
        if out in seen:
            continue
        seen.add(out)
        score = max(assess(out)[0], flag_plausibility(out))
        yield out, "hill3-crib", {"rot": rot, "start": start}, score


# ------------------------------------------------------------ extra encodings
def _bits_to_bytes(bits):
    bits = bits[:len(bits) - len(bits) % 8]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _dna_decode(text):
    m = {"A": "00", "C": "01", "G": "10", "T": "11"}
    bits = []
    for ch in text.upper():
        if ch not in m:
            return None
        bits.append(m[ch])
    return _bits_to_bytes("".join(bits))


def _two_symbol_decode(text, s0, s1):
    bits = []
    for ch in text:
        if ch == s0:
            bits.append("0")
        elif ch == s1:
            bits.append("1")
        else:
            return None
    return _bits_to_bytes("".join(bits))


def _braille_decode(text):
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp in (10, 13, 9, 32):
            continue
        if 0x2800 <= cp <= 0x28ff:
            out.append(cp & 0xff)
        else:
            return None
    return bytes(out)


_B32HEX_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_CROCKFORD_ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _alphabet_b32_decode(text, alph):
    rev = {c: i for i, c in enumerate(alph)}
    bits = []
    for ch in text.upper():
        if ch not in rev:
            return None
        bits.append(f"{rev[ch]:05b}")
    s = "".join(bits)
    s = s[:len(s) - len(s) % 8]
    return _bits_to_bytes(s)


def _swapped_b64_decode(text):
    swapped = "".join(ch.swapcase() if ch.isalpha() else ch for ch in text)
    try:
        return base64.b64decode(swapped + "=" * ((-len(swapped)) % 4))
    except (binascii.Error, ValueError):
        return None


def _extra_enc_prior(fp):
    if fp["charset"] not in ("ascii-text", "mixed", "binary"):
        return 0.0
    t = fp.get("_text", "").strip()
    if not t:
        # maybe non-ASCII (e.g. Braille) text; let the solver try UTF-8.
        return .3 if fp["charset"] == "binary" else 0.0
    if re.fullmatch(r"[ACGTacgt\s]+", t) and len(re.sub(r"\s", "", t)) >= 8:
        return .6
    if re.fullmatch(r"[.#\s]+", t) and len(re.sub(r"\s", "", t)) >= 8:
        return .6
    if re.fullmatch(r"[ABab\s]+", t) and len(re.sub(r"\s", "", t)) >= 8:
        return .6
    if t and all(0x2800 <= ord(c) <= 0x28ff for c in t):
        return .7
    if re.fullmatch(r"[0-9A-Va-v=+\s]+", t) and len(re.sub(r"\s", "", t).rstrip("=")) % 8 in (0, 1, 2, 3, 4, 5, 6, 7):
        return .5
    return 0.0


@solver("extra-encodings", _extra_enc_prior)
def solve_extra_encodings(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    compact = re.sub(r"\s", "", text)
    attempts = []
    dna = _dna_decode(compact)
    if dna:
        attempts.append((dna, "dna"))
    for s0, s1 in ((".", "#"), ("A", "B"), ("0", "1"), ("X", "Y")):
        if all(c in (s0, s1) for c in compact):
            out = _two_symbol_decode(compact, s0, s1)
            if out:
                attempts.append((out, f"two-symbol {s0}{s1}"))
    braille = _braille_decode(text)
    if braille:
        attempts.append((braille, "braille"))
    b32hex = _alphabet_b32_decode(compact, _B32HEX_ALPH)
    if b32hex:
        attempts.append((b32hex, "base32hex"))
    ck = _alphabet_b32_decode(compact, _CROCKFORD_ALPH)
    if ck:
        attempts.append((ck, "crockford"))
    sw = _swapped_b64_decode(compact)
    if sw:
        attempts.append((sw, "swapped-case base64"))
    seen = set()
    for out, name in attempts:
        if out in seen:
            continue
        seen.add(out)
        score, _ = assess(out)
        yield out, name, {}, score


def _byte_transform_prior(fp):
    if fp["charset"] == "ascii-text":
        return 0.0  # skip when already printable text
    if fp["length"] < 8:
        return 0.0
    return .5


@solver("byte-transforms", _byte_transform_prior)
def solve_byte_transforms(data, ctx):
    n = len(data)
    seen = set()
    for x in range(256):
        if ctx.expired():
            return
        cands = []
        cands.append(bytes((b + x) % 256 for b in data))
        cands.append(bytes((b - x) % 256 for b in data))
        cands.append(bytes(((b << x) | (b >> (8 - x))) & 0xff for b in data) if x > 0 else data)
        cands.append(bytes(((b >> x) | (b << (8 - x))) & 0xff for b in data) if x > 0 else data)
        for out in cands:
            if out in seen:
                continue
            pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / n
            if pr >= .9:
                seen.add(out)
                score, _ = assess(out)
                yield out, "byte-transform", {"key": x}, score
