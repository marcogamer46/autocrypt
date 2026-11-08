"""Pack 6: Four-square, Gronsfeld, straddling checkerboard, base-N/Z85,
ECDSA/DLP, Merkle-Hellman, Enigma M3."""
from __future__ import annotations

import math
import re

from autocrypt.core import solver
from autocrypt.scoring import assess, quadgram_score, flag_plausibility, english_confidence
import autocrypt.solvers as S

_ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # I/J merged


def _polybius_sq(keyword):
    key = "".join(dict.fromkeys((keyword.upper() + _ALPHA25).replace("J", "I")))[:25]
    return [key[i * 5:(i + 1) * 5] for i in range(5)]


# ---------------------------------------------------------------- Four-square
_FOURSQUARE_KEYS = [("", ""), ("KEYWORD", "SECRET"), ("CIPHER", "LEMON"),
                    ("CRYPTO", "VICTOR"), ("MOSCOW", "MANCHESTER"),
                    ("MONARCHY", "PLAYFAIR")]


def _sq_pos(sq):
    return {ch: (r, c) for r, row in enumerate(sq) for c, ch in enumerate(row)}


def _foursquare_decrypt(text, kw1, kw2):
    tl = _polybius_sq("")
    br = _polybius_sq("")
    pos_tr = _sq_pos(_polybius_sq(kw1))
    pos_bl = _sq_pos(_polybius_sq(kw2))
    out = []
    for i in range(0, len(text) - 1, 2):
        x, y = text[i], text[i + 1]
        if x not in pos_tr or y not in pos_bl:
            return None
        r1, c2 = pos_tr[x]
        r2, c1 = pos_bl[y]
        out += [tl[r1][c1], br[r2][c2]]
    return "".join(out)


def _foursquare_prior(fp):
    if fp["charset"] != "ascii-text" or not 20 <= fp["length"] <= 5000:
        return 0.0
    t = fp.get("_text", "").strip()
    letters = "".join(ch for ch in t if ch.isalpha())
    if len(letters) < 12 or len(letters) % 2:
        return 0.0
    return .4


@solver("four-square", _foursquare_prior)
def solve_foursquare(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    letters = "".join(ch for ch in text if ch.isalpha()).upper().replace("J", "I")
    if len(letters) < 12 or len(letters) % 2:
        return
    variants = []
    for kw1, kw2 in _FOURSQUARE_KEYS:
        if ctx.expired():
            return
        out = _foursquare_decrypt(letters, kw1, kw2)
        if out and out not in [v[0] for v in variants]:
            variants.append((out, kw1, kw2))
    scored = [(quadgram_score(out), out, kw1, kw2) for out, kw1, kw2 in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, out, kw1, kw2 in scored:
        if out not in seen:
            seen.add(out)
            uniq.append((q, out, kw1, kw2))
    boost = len(uniq) >= 2 and uniq[0][0] - uniq[1][0] >= .35
    for i, (_, out, kw1, kw2) in enumerate(uniq[:3]):
        params = {"key1": kw1 or "default", "key2": kw2 or "default"}
        if i == 0 and boost:
            params["_statistical"] = True
            yield out, "four-square", params, .80
        else:
            yield out, "four-square", params, max(assess(out)[0], flag_plausibility(out))


# ---------------------------------------------------------------- Gronsfeld
_EN_FREQ26 = [.08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094,
              .06966, .00153, .00772, .04025, .02406, .06749, .07507, .01929,
              .00095, .05987, .06327, .09056, .02758, .00978, .02360, .00150,
              .01974, .00074]


def _gronsfeld_decrypt(text, key):
    out = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr(base + (ord(ch) - base - key[i % len(key)]) % 26))
        else:
            out.append(ch)
    return "".join(out)


def _gronsfeld_best_key(letters, length):
    key = []
    for j in range(length):
        col = letters[j::length]
        best_d, best_s = 0, -1.0
        for d in range(10):
            s = sum(_EN_FREQ26[(ord(c) - 65 - d) % 26] for c in col)
            if s > best_s:
                best_d, best_s = d, s
        key.append(best_d)
    return key


def _gronsfeld_prior(fp):
    if fp["charset"] != "ascii-text" or not 20 <= fp["length"] <= 5000:
        return 0.0
    t = fp.get("_text", "").strip()
    letters = "".join(ch for ch in t if ch.isalpha())
    if len(letters) < 15:
        return 0.0
    return .4


@solver("gronsfeld", _gronsfeld_prior)
def solve_gronsfeld(data, ctx):
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
        key = _gronsfeld_best_key(letters, length)
        out = _gronsfeld_decrypt(letters, key)
        if out and (out, tuple(key)) not in [(v[0], tuple(v[1])) for v in variants]:
            variants.append((out, key))
    scored = [(quadgram_score(out), out, key) for out, key in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, out, key in scored:
        if out not in seen:
            seen.add(out)
            uniq.append((q, out, key))
    uniq.sort(key=lambda t: (-english_confidence(t[1]), len(t[2])))
    boost = len(uniq) >= 2 and english_confidence(uniq[0][1]) >= .5 \
        and english_confidence(uniq[0][1]) >= english_confidence(uniq[1][1])
    for i, (_, out, key) in enumerate(uniq[:3]):
        params = {"key": "".join(map(str, key))}
        if i == 0 and boost:
            params["_statistical"] = True
            yield out, "gronsfeld", params, min(0.95, 0.55 + 0.35 * english_confidence(out))
        else:
            yield out, "gronsfeld", params, max(assess(out)[0], flag_plausibility(out))


# ------------------------------------------------------ straddling checkerboard
_SCD_LAYOUTS = [
    # blanks (8,9): top A-H on digits 0-7; 8-row K..T; 9-row U..Z .-/?
    ((8, 9), "ABCDEFGH", "KLMNOPQRST", "UVWXYZ.-/?"),
    # blanks (0,1): top A-H on digits 2-9; 0-row I..R; 1-row S..Z .
    ((0, 1), "ABCDEFGH", "IJKLMNOPQ", "RSTUVWXYZ."),
]


def _scd_decrypt(digits, blanks, top, row1, row2):
    top_map = {d: ch for d, ch in zip((i for i in range(10) if i not in blanks), top)}
    if len(top_map) != len(top):
        return None
    b1, b2 = blanks
    out = []
    i = 0
    while i < len(digits):
        d = digits[i]
        if d in top_map:
            out.append(top_map[d])
            i += 1
        elif d == b1 and i + 1 < len(digits) and digits[i + 1] < len(row1):
            out.append(row1[digits[i + 1]])
            i += 2
        elif d == b2 and i + 1 < len(digits) and digits[i + 1] < len(row2):
            out.append(row2[digits[i + 1]])
            i += 2
        else:
            return None
    return "".join(out)


def _scd_prior(fp):
    if fp["charset"] != "ascii-text" or not 15 <= fp["length"] <= 5000:
        return 0.0
    t = fp.get("_text", "").strip()
    if not re.fullmatch(r"[0-9\s]+", t):
        return 0.0
    return .5


@solver("straddling-checkerboard", _scd_prior)
def solve_scd(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 15:
        return
    variants = []
    for blanks, top, row1, row2 in _SCD_LAYOUTS:
        if ctx.expired():
            return
        out = _scd_decrypt(digits, blanks, top, row1, row2)
        if out and out not in [v[0] for v in variants]:
            variants.append((out, blanks))
    scored = [(quadgram_score(out), out, blanks) for out, blanks in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, out, blanks in scored:
        if out not in seen:
            seen.add(out)
            uniq.append((q, out, blanks))
    boost = len(uniq) >= 2 and uniq[0][0] - uniq[1][0] >= .35
    for i, (_, out, blanks) in enumerate(uniq[:3]):
        params = {"blanks": str(blanks)}
        if i == 0 and boost:
            params["_statistical"] = True
            yield out, "straddling-checkerboard", params, .80
        else:
            yield out, "straddling-checkerboard", params, max(assess(out)[0], flag_plausibility(out))


# --------------------------------------------------------- Z85 (RFC 1924)
_Z85_ALPH = ("0123456789abcdefghijklmnopqrstuvwxyz"
              "ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
_Z85_SIZES = {5: 4, 4: 3, 3: 2, 2: 1, 1: 0}


def _z85_decode(s):
    if len(s) % 5 == 1:
        return None
    out = bytearray()
    for i in range(0, len(s), 5):
        group = s[i:i + 5]
        v = 0
        for ch in group:
            idx = _Z85_ALPH.find(ch)
            if idx < 0:
                return None
            v = v * 85 + idx
        n = _Z85_SIZES.get(len(group))
        if n is None or v >= 85 ** len(group):
            return None
        out += v.to_bytes(n, "big")
    return bytes(out)


def _z85_prior(fp):
    if fp["charset"] != "ascii-text" or fp["length"] < 8:
        return 0.0
    t = fp.get("_text", "").strip()
    if t and all(c in _Z85_ALPH for c in t):
        return .7
    return 0.0


@solver("z85", _z85_prior)
def solve_z85(data, ctx):
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return
    out = _z85_decode(text)
    if out:
        score, _ = assess(out)
        yield out, "z85", {}, score


# ------------------------------------------------- custom alphabet base decoding
def _custom_base_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    return .9 if re.search(r"\b(?:alphabet|charset|alpha)\s*[:=]", t, re.I) else 0.0


@solver("custom-alphabet-base", _custom_base_prior)
def solve_custom_base(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    m = re.search(r"\b(?:alphabet|charset|alpha)\s*[:=]\s*([^\n\r]+)", text, re.I)
    if not m:
        return
    alpha = m.group(1).strip().strip('"\'')
    if len(alpha) < 2 or len(set(alpha)) != len(alpha):
        return
    dm = re.search(r"\b(?:data|encoded|msg|ct|cipher|value)\s*[:=]\s*([A-Za-z0-9+/=]+)", text, re.I)
    tok = dm.group(1).strip() if dm else None
    if not tok:
        tok = (t for t in text.splitlines() if t.strip() and "=" not in t)
        tok = next(tok, "").strip()
    if not tok or any(c not in alpha for c in tok):
        return
    v = 0
    for ch in tok:
        v = v * len(alpha) + alpha.index(ch)
    n = max(1, (v.bit_length() + 7) // 8)
    out = v.to_bytes(n, "big")
    if out:
        score, _ = assess(out)
        yield out, "custom-base", {"base": len(alpha)}, score


# ------------------------------------------------ EC arithmetic / DLP / ECDSA
def _ec_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_mul(k, P, a, p):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, a, p)
        P = _ec_add(P, P, a, p)
        k >>= 1
    return R


def _bsgs(P, Q, m, a, p):
    """Solve Q = kP for 0 <= k < m (order m) by baby-step giant-step."""
    s = math.isqrt(m) + 1
    table = {}
    cur = None
    for j in range(s):
        table[cur] = j
        cur = P if cur is None else _ec_add(cur, P, a, p)
    step = _ec_mul(s, P, a, p)
    gamma = Q
    neg_step = None if step is None else (step[0], (-step[1]) % p)
    for i in range(s + 1):
        if gamma in table:
            k = table[gamma] + i * s
            if _ec_mul(k, P, a, p) == Q:
                return k
        if gamma is None:
            break
        gamma = _ec_add(gamma, neg_step, a, p)
    return None


def _trial_smooth(n, limit=2_000_000):
    """Split n into prime powers by trial division (for smooth orders)."""
    fac = []
    d = 2
    while d * d <= n and d <= limit:
        if n % d == 0:
            e = 0
            while n % d == 0:
                n //= d
                e += 1
            fac.append((d, e))
        d += 1 if d == 2 else 2
    if n > 1:
        fac.append((n, 1))
    return fac


def _ph_dlp(P, Q, n, a, p, ctx):
    """Pohlig-Hellman: Q = kP where ord(P) = n; returns k or None."""
    rem, mod = [], []
    for q, e in _trial_smooth(n):
        ne = q ** e
        if ne > 2 ** 22:      # keep BSGS practical
            return None
        Pi = _ec_mul(n // ne, P, a, p)
        Qi = _ec_mul(n // ne, Q, a, p)
        xi = _bsgs(Pi, Qi, ne, a, p)
        if xi is None:
            return None
        rem.append(xi)
        mod.append(ne)
    x = 0
    for r, m in zip(rem, mod):
        M = math.prod(mod) // m
        x += r * M * pow(M, -1, m)
    return x % math.prod(mod)


def _ec_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    if re.search(r"\b(?:p|n)\s*[:=]", t) and re.search(r"\b(?:a|b)\s*[:=]", t):
        return .8
    return 0.0


def _parse_ec(text):
    v = {}
    for k, val in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*(-?0x[0-9a-fA-F]+|-?\d+)", text):
        v.setdefault(k.lower(), int(val, 0))
    def pt(labels):
        for lab in labels:
            x = v.get(lab + "x")
            y = v.get(lab + "y")
            if x is not None and y is not None:
                return (x, y)
        m = re.search(r"\b(?:G|Q)\s*[:=]\s*\(?\s*(\d+)\s*,\s*(\d+)\s*\)?", text)
        return (int(m.group(1)), int(m.group(2))) if m else None
    return v, pt


@solver("ecdlp", _ec_prior)
def solve_ecdlp(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v, pt = _parse_ec(text)
    p = v.get("p")
    n = v.get("n")
    if not p or not n or p < 2 or n < 2:
        return
    a = v.get("a", 0)
    b = v.get("b", 0)
    P = pt(("g",))
    Q = pt(("q",))
    if not P or not Q:
        return
    k = _ph_dlp(P, Q, n, a, p, ctx)
    if k is not None:
        yield f"k={k}".encode(), "Cracked EC-DLP", {"order": n}, .98


@solver("ecdsa-nonce-reuse", _ec_prior)
def solve_ecdsa_reuse(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    v, pt = _parse_ec(text)
    n = v.get("n")
    if not n or n < 2:
        return
    r = v.get("r")
    s1, s2 = v.get("s1"), v.get("s2")
    z1, z2 = v.get("z1"), v.get("z2")
    if r is None or s1 is None or s2 is None or z1 is None or z2 is None:
        return
    try:
        k = (z1 - z2) * pow(s1 - s2, -1, n) % n
        d = (s1 * k - z1) * pow(r, -1, n) % n
    except (ValueError, ZeroDivisionError):
        return
    if pt(("q",)):
        Q = pt(("q",))
        a = v.get("a", 0)
        p = v.get("p", 0)
        g = pt(("g",))
        if p and g and _ec_mul(d, g, a, p) != Q:
            return
    yield f"d={d} k={k}".encode(), "Cracked ECDSA nonce reuse", {"n": n}, .98


# --------------------------------------------------- Merkle-Hellman knapsack
def _subsetsum_mitm(vals, target):
    n = len(vals)
    h = n // 2
    left = {}
    for mask in range(1 << h):
        s = 0
        mm = mask
        j = 0
        while mm:
            if mm & 1:
                s += vals[j]
            mm >>= 1
            j += 1
        left.setdefault(s, mask)
    for mask2 in range(1 << (n - h)):
        s2 = 0
        mm = mask2
        j = 0
        while mm:
            if mm & 1:
                s2 += vals[h + j]
            mm >>= 1
            j += 1
        need = target - s2
        if need in left:
            return left[need] | (mask2 << h)
    return None


def _greedy_superinc(vals, target):
    mask = 0
    for i in range(len(vals) - 1, -1, -1):
        if vals[i] <= target:
            target -= vals[i]
            mask |= 1 << i
    return mask if target == 0 else None


def _mh_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    if re.search(r"\ba\s*=\s*\[", t) and re.search(r"\bc\s*[:=]", t):
        return .85
    return 0.0


@solver("merkle-hellman", _mh_prior)
def solve_merkle_hellman(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    m = re.search(r"\ba\s*=\s*\[([^\]]+)\]", text)
    if not m:
        m = re.search(r"\ba\s*=\s*([0-9,\s]+)", text)
    if not m:
        return
    try:
        vals = [int(x) for x in re.findall(r"\d+", m.group(1))]
    except ValueError:
        return
    cm = re.search(r"\bc\s*[:=]\s*(\d+)", text)
    if not cm or not vals:
        return
    c = int(cm.group(1))
    n = len(vals)
    if n < 12 or n > 44:
        return
    mask = None
    how = None
    wm = re.search(r"\bw\s*[:=]\s*(\d+)", text)
    mm = re.search(r"\bm\s*[:=]\s*(\d+)", text)
    if wm and mm:
        w = int(wm.group(1))
        mod = int(mm.group(1))
        try:
            invw = pow(w, -1, mod)
        except ValueError:
            invw = None
        if invw:
            red = [(x * invw) % mod for x in vals]
            t = (c * invw) % mod
            mask = _greedy_superinc(red, t)
            how = "superincreasing"
    if mask is None:
        mask = _subsetsum_mitm(vals, c)
        how = "meet-in-the-middle"
    if mask is None:
        return
    out = mask.to_bytes((n + 7) // 8, "big")
    yield out, f"Cracked knapsack ({how})", {"n": n}, .98


# -------------------------------------------------------------- Enigma M3
_ENIGMA_ROTORS = {
    "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}
_ENIGMA_REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}


class _EnigmaRotor:
    __slots__ = ("wiring", "notch", "ring", "pos")

    def __init__(self, wiring, notch, ring, pos):
        self.wiring = [ord(c) - 65 for c in wiring]
        self.notch = ord(notch) - 65
        self.ring = ring % 26
        self.pos = pos % 26

    def output(self, i, reverse=False):
        p = (i + self.pos - self.ring) % 26
        w = self.wiring.index(p) if reverse else self.wiring[p]
        return (w - self.pos + self.ring) % 26

    def step(self):
        self.pos = (self.pos + 1) % 26


def _enigma_machine(rotor_names, rings, positions, reflector="B"):
    rotors = [_EnigmaRotor(*_ENIGMA_ROTORS[n], ring, pos)
              for n, ring, pos in zip(rotor_names, rings, positions)]
    ref = [ord(c) - 65 for c in _ENIGMA_REFLECTORS[reflector]]
    return rotors, ref


def _enigma_encrypt(text, rotor_names, rings, positions, reflector, plugboard):
    rotors, ref = _enigma_machine(rotor_names, rings, positions, reflector)
    pb = {}
    for pair in plugboard:
        if len(pair) == 2:
            a, b = pair[0], pair[1]
            pb[a] = b
            pb[b] = a
    out = []
    for ch in text:
        if not ch.isalpha():
            out.append(ch)
            continue
        if rotors[1].pos == rotors[1].notch:
            rotors[1].step()
            rotors[0].step()
        if rotors[2].pos == rotors[2].notch:
            rotors[1].step()
        rotors[2].step()
        x = ord(ch.upper()) - 65
        x = pb.get(chr(x + 65), chr(x + 65))
        x = ord(x) - 65
        for r in reversed(rotors):
            x = r.output(x)
        x = ref[x]
        for r in rotors:
            x = r.output(x, reverse=True)
        x = pb.get(chr(x + 65), chr(x + 65))
        out.append(chr(ord(x)))
    return "".join(out)


def _parse_plugboard(text):
    m = re.search(r"\b(?:plugboard|stecker)\s*[:=]\s*([A-Z ]+)", text, re.I)
    if not m:
        return []
    return re.findall(r"[A-Z]{2}", m.group(1).upper())


def _enigma_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    return .8 if re.search(r"\b(?:rotor|enigma)\w*\s*[:=]", t, re.I) else 0.0


@solver("enigma-m3", _enigma_prior)
def solve_enigma(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    # Ciphertext is the part that is not a key=value settings line.
    letters = "".join(ch for line in text.splitlines() if "=" not in line
                      for ch in line if ch.isalpha()).upper()
    if len(letters) < 12:
        return
    v = {}
    for k, val in re.findall(r"\b([A-Za-z_]\w*)\s*[:=]\s*([^\n\r]+)", text):
        v.setdefault(k.lower(), val.strip())
    names = re.findall(r"[IVX]+", v.get("rotors", "") or v.get("enigma_rotors", ""))
    names = [n for n in names if n in _ENIGMA_ROTORS] or ["I", "II", "III"]
    rings = [ord(c) - 65 for c in v.get("rings", "AAA")[:3]]
    positions = [ord(c) - 65 for c in v.get("positions", v.get("pos", "AAA"))[:3]]
    reflector = v.get("reflector", "B").upper()
    if reflector not in _ENIGMA_REFLECTORS:
        reflector = "B"
    plugboard = _parse_plugboard(text)
    crib = (ctx.known_plaintext or "").upper()
    crib = "".join(ch for ch in crib if ch.isalpha())
    # Settings fully specified -> direct decrypt (exact).
    if v.get("positions") or v.get("pos"):
        out = _enigma_encrypt(letters, names, rings, positions, reflector, plugboard)
        params = {"rotors": "".join(names), "positions": v.get("positions", v.get("pos", "AAA")),
                  "_statistical": True}
        yield out, "Enigma M3", params, .9
        return
    # Crib-guided brute force over rotor order x initial positions.
    if len(crib) < 4:
        return
    import itertools
    window = letters[:max(4, len(crib))]
    for order in itertools.permutations(names[:3] if len(names) <= 3 else names[0:3]):
        if ctx.expired():
            return
        for a in range(26):
            for b in range(26):
                for c in range(26):
                    if ctx.expired():
                        return
                    # Cheap precheck on a short window; only a full decrypt on match.
                    if _enigma_encrypt(window, order, rings, (a, b, c), reflector, plugboard) != crib:
                        continue
                    out = _enigma_encrypt(letters, order, rings, (a, b, c), reflector, plugboard)
                    if crib in out:
                        yield out, f"Cracked Enigma M3 (rotors={''.join(order)}, pos={chr(65+a)}{chr(65+b)}{chr(65+c)})", {"reflector": reflector, "_statistical": True}, .98
                        return
