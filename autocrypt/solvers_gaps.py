"""Gap-filling solvers for CTF staples missing from earlier modules.

Each solver degrades gracefully (returns nothing) when its trigger condition
isn't present. These cover:

  * PowerShell ``-EncodedCommand`` (base64 of UTF-16LE) - ``powershell-encodedcommand``
  * Unicode tag characters (U+E0000..E007F map to ASCII) - ``unicode-tag-stego``
  * ``java.util.Random`` seed recovery from consecutive ``nextInt()`` outputs - ``java-random``
  * JWT RS256->HS256 key-confusion (asymmetric alg verified with the public
    key as an HMAC secret) - ``jwt-key-confusion``

The RSA/HMAC primitives are implemented locally so this module stays
self-contained and easy to audit.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import struct

from autocrypt.core import solver
from autocrypt.scoring import assess


def _emit(ctx, plain, method, params=None, score=None):
    params = params or {}
    if score is None:
        score, _ = assess(plain)
    yield plain, method, params, score


# ------------------------------------------------------- PowerShell -EncodedCommand
_PSE_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")


@solver("powershell-encodedcommand", lambda fp: .40
        if fp.get("charset") in ("ascii-text", "mixed") and fp["length"] >= 8 else 0.0)
def solve_powershell_encoded(data, ctx):
    """``powershell -EncodedCommand`` is base64 of UTF-16LE text."""
    if not _PSE_RE.match(data[:4096]) or len(data) < 16:
        return
    t = re.sub(rb"\s+", b"", data)
    if len(t) % 4 != 0 or len(t) > 200_000:
        return
    try:
        raw = base64.b64decode(t, validate=True)
    except Exception:
        return
    if not raw or len(raw) < 4:
        return
    # UTF-16LE heuristic: BOM, or NULs on alternating byte positions.
    utf16le = False
    if raw[:2] == b"\xff\xfe":
        utf16le = True
    else:
        if len(raw) % 2:
            raw = raw[:-1]
        if len(raw) >= 6:
            zeros = raw[1::2].count(0) + raw[0::2].count(0)
            if zeros >= max(2, len(raw) // 8):
                utf16le = True
    if not utf16le:
        return
    try:
        s = raw.decode("utf-16-le")
    except Exception:
        return
    s = s.strip()
    if not s:
        return
    score, _ = assess(s)
    if score < 0.15 and "{" not in s:
        return
    yield from _emit(ctx, s.encode("utf-8", "replace"),
                     "PowerShell -EncodedCommand (base64 of UTF-16LE)", score=score)


# ------------------------------------------------------- Unicode tag stego
_TAG_BASE = 0xE0000


@solver("unicode-tag-stego", lambda fp: .50 if fp.get("_tags") else 0.0)
def solve_unicode_tag_stego(data, ctx):
    """Unicode tag characters U+E0000..E007F are ASCII + 0xE0000."""
    text = data.decode("utf-8", "replace")
    out = []
    for ch in text:
        cp = ord(ch)
        if _TAG_BASE <= cp <= _TAG_BASE + 0x7F:
            out.append(chr(cp - _TAG_BASE))
    dec = "".join(out).strip()
    if not dec:
        return
    score, _ = assess(dec)
    if score < 0.15 and "{" not in dec:
        return
    ctx.findings.append(f"Decoded {len(dec)} Unicode tag characters to ASCII.")
    yield from _emit(ctx, dec.encode("utf-8", "replace"),
                     "Unicode tag steganography", {"count": len(dec)}, score=score)


# ------------------------------------------------------- java.util.Random recovery
_RND_A = 0x5DEECE66D
_RND_B = 0xB
_RND_MASK = (1 << 48) - 1


def _rnd_next(s):
    return (s * _RND_A + _RND_B) & _RND_MASK


def _java_random_seeds(v0, v1):
    """Recover the 48-bit states whose high 32 bits match output v0, and
    whose successor state's high 32 bits match output v1 (i.e. states right
    after output v0 was generated)."""
    found = []
    for lo in range(1 << 16):
        old = (v0 << 16) | lo
        new = _rnd_next(old)
        if (new >> 16) == v1:
            found.append(old)
            if len(found) > 64:
                break
    return found


@solver("java-random", lambda fp: .35
        if fp.get("charset") in ("ascii-text", "mixed") and fp.get("_text") and
        len(re.findall(r"\d+", fp["_text"])) >= 3 else 0.0)
def solve_java_random(data, ctx):
    """Recover a ``java.util.Random`` seed from consecutive nextInt() outputs."""
    text = data.decode("utf-8", "replace")
    vals = [int(x) for x in re.findall(r"-?\d+", text)]
    if len(vals) < 3:
        return
    u = [v & 0xFFFFFFFF for v in vals[:8]]
    seeds = _java_random_seeds(u[0], u[1])
    if not seeds:
        return
    best = None
    for s0 in seeds:
        st = s0
        match = 1
        for k in range(1, len(u)):
            st = _rnd_next(st)
            if (st >> 16) == u[k]:
                match += 1
            else:
                break
        if best is None or match > best[0]:
            best = (match, s0)
    if best is None or best[0] < max(3, len(u) - 1):
        return
    s0 = best[1]
    # Invert the LCG to recover the java.util.Random constructor seed.
    _inv = pow(_RND_A, -1, 1 << 48)
    seed = (((s0 - _RND_B) * _inv) & _RND_MASK) ^ _RND_A
    st = (seed ^ _RND_A) & _RND_MASK
    pred = []
    for _ in range(len(u) + 6):
        st = _rnd_next(st)
        pred.append(st >> 16)
    signed = [p - (1 << 32) if p >= (1 << 31) else p for p in pred]
    ctx.findings.append(f"java.util.Random seed recovered: {seed} "
                        f"(matched {best[0]} outputs).")
    note = (f"java.util.Random seed {seed} (0x{seed:x}); next outputs: "
            + ", ".join(str(x) for x in signed[len(u):]))
    yield from _emit(ctx, note.encode(), "java util.Random PRNG recovery",
                     {"seed": seed, "matched": best[0]}, score=.3)


# ------------------------------------------------------- JWT RS256->HS256 confusion
_JWT_RE = re.compile(rb"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])")
_PEM_RE = re.compile(rb"-----BEGIN [A-Z ]*PUBLIC KEY-----([\s\S]*?)-----END [A-Z ]*PUBLIC KEY-----")


def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@solver("jwt-key-confusion", lambda fp: .60
        if bool(fp.get("prior_map", {}).get("jwt")) and bool(fp.get("prior_map", {}).get("pem")) else 0.0)
def solve_jwt_key_confusion(data, ctx):
    """Forge/verify a JWT whose alg is asymmetric but whose signature is an
    HMAC keyed with the RSA public key (RS256->HS256 confusion)."""
    pem = _PEM_RE.search(data)
    if not pem:
        return
    try:
        der = base64.b64decode(re.sub(rb"\s+", b"", pem.group(1)))
    except Exception:
        return
    if not der:
        return
    for tok_m in _JWT_RE.finditer(data):
        tok = tok_m.group(0).decode("ascii", "replace")
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        try:
            head = _b64url_decode(parts[0])
            alg = ""
            m = re.search(rb'"alg"\s*:\s*"([A-Za-z0-9_]+)"', head)
            if m:
                alg = m.group(1).decode()
            if not alg or alg == "none" or alg.startswith("HS"):
                continue
            payload = _b64url_decode(parts[1])
            sig = _b64url_decode(parts[2])
        except Exception:
            continue
        message = (parts[0] + "." + parts[1]).encode("ascii")
        # try the DER public key and the raw PEM text as HMAC secrets
        for key in (der, pem.group(0)):
            if hmac.new(key, message, hashlib.sha256).digest() == sig:
                try:
                    plain = payload.decode("utf-8", "replace")
                except Exception:
                    plain = payload.decode("latin-1", "replace")
                yield from _emit(ctx, plain.encode("utf-8", "replace"),
                                 "JWT HS256 key confusion (RS256 header)",
                                 {"alg": alg}, score=.9)
                return


# ------------------------------------------------------- Unicode big-base decode
def _bigbase_decode(text, base, lo, hi):
    """Decode a big-integer expressed in `base` where each digit maps to the
    code point ``lo + digit``. Digits are read most-significant first (the
    common base100/base65536 writer order); the reverse order is tried too."""
    digits = [ord(ch) - lo for ch in text if lo <= ord(ch) <= hi]
    if len(digits) < 4:
        return None
    for rev in (False, True):
        ds = digits[::-1] if rev else digits
        n = 0
        for d in ds:
            n = n * base + d
        if n <= 0:
            continue
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        cut = raw.find(b"\x00")
        txt = raw[:cut] if 4 < cut < len(raw) else raw
        if not txt:
            continue
        score, _ = assess(txt)
        flaggy = re.search(rb"[A-Za-z0-9_]{2,20}\{", txt)
        if score >= 0.25 or flaggy:
            return txt, score, rev
    return None


@solver("base100-decode", lambda fp: .45 if fp.get("_han") else 0.0)
def solve_base100(data, ctx):
    """base100 (qntm-style): a big integer in base 11172 written as Hangul
    syllables U+AC00..D7A3."""
    text = data.decode("utf-8", "replace")
    r = _bigbase_decode(text, 11172, 0xAC00, 0xD7A3)
    if r is None:
        return
    txt, score, rev = r
    ctx.findings.append(f"Decoded {len([c for c in text if 0xAC00 <= ord(c) <= 0xD7A3])} "
                        "Hangul syllables as a base-11172 integer.")
    yield from _emit(ctx, txt, "base100 (Hangul) decode", {"rev": rev},
                     score=max(score, 0.35))


# ------------------------------------------------------- hash length extension
# MD5 / SHA-1 length-extension primitives. Given a MAC
# ``mac = hash(secret || message)`` and the length of the secret, these
# compute ``hash(secret || message || pad || append)`` without knowing the
# secret. The auto-detection of a suitable challenge is inherently limited
# (it needs an oracle/known appended target), so these are exposed as correct,
# unit-tested helpers rather than an aggressive solver.
def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


_MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]
_MD5_S = (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
          5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21)


def _md5_compress(st, block):
    a, b, c, d = st
    m = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]
    aa, bb, cc, dd = a, b, c, d
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            k = i
        elif i < 32:
            f = (d & b) | (~d & c)
            k = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            k = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d)
            k = (7 * i) % 16
        tmp = (a + f + m[k] + _MD5_K[i]) & 0xFFFFFFFF
        tmp = _rol(tmp, _MD5_S[i])
        a, b, c, d = d, (b + tmp) & 0xFFFFFFFF, b, c
    return ((a + aa) & 0xFFFFFFFF, (b + bb) & 0xFFFFFFFF,
            (c + cc) & 0xFFFFFFFF, (d + dd) & 0xFFFFFFFF)


def _md5_pad(total_len):
    bitlen = total_len * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (total_len + 1) % 64) % 64)
    pad += struct.pack("<Q", bitlen)
    return pad


def _md5_extend(digest, orig_len_bytes, append):
    """digest = md5(secret || msg) (with its padding already absorbed into the
    state); orig_len_bytes = len(secret)+len(msg).  Returns
    md5(secret || msg || pad(orig_len_bytes) || append)."""
    a, b, c, d = struct.unpack("<4I", digest)
    # The restored state already includes the padding for orig_len_bytes, so
    # we resume by hashing `append`; its final block is keyed to the true
    # total length (including the glue padding and the append itself).
    total_len = orig_len_bytes + len(_md5_pad(orig_len_bytes)) + len(append)
    feed = append
    while len(feed) >= 64:
        a, b, c, d = _md5_compress((a, b, c, d), feed[:64])
        feed = feed[64:]
    last = feed + b"\x80" + b"\x00" * ((56 - (len(feed) + 1) % 64) % 64)
    last += struct.pack("<Q", total_len * 8)
    for i in range(0, len(last), 64):
        a, b, c, d = _md5_compress((a, b, c, d), last[i:i + 64])
    return struct.pack("<4I", a, b, c, d)


_SHA1_K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)


def _sha1_compress(st, block):
    h0, h1, h2, h3, h4 = st
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 80):
        w.append(_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d)
            k = _SHA1_K[0]
        elif i < 40:
            f = b ^ c ^ d
            k = _SHA1_K[1]
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = _SHA1_K[2]
        else:
            f = b ^ c ^ d
            k = _SHA1_K[3]
        tmp = (_rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, _rol(b, 30), a, tmp
    return ((h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF,
            (h2 + c) & 0xFFFFFFFF, (h3 + d) & 0xFFFFFFFF,
            (h4 + e) & 0xFFFFFFFF)


def _sha1_pad(total_len):
    bitlen = total_len * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (total_len + 1) % 64) % 64)
    pad += struct.pack(">Q", bitlen)
    return pad


def _sha1_extend(digest, orig_len_bytes, append):
    """Counterpart of _md5_extend for SHA-1 (big-endian length)."""
    h0, h1, h2, h3, h4 = struct.unpack(">5I", digest)
    total_len = orig_len_bytes + len(_sha1_pad(orig_len_bytes)) + len(append)
    feed = append
    while len(feed) >= 64:
        h0, h1, h2, h3, h4 = _sha1_compress((h0, h1, h2, h3, h4), feed[:64])
        feed = feed[64:]
    last = feed + b"\x80" + b"\x00" * ((56 - (len(feed) + 1) % 64) % 64)
    last += struct.pack(">Q", total_len * 8)
    for i in range(0, len(last), 64):
        h0, h1, h2, h3, h4 = _sha1_compress((h0, h1, h2, h3, h4), last[i:i + 64])
    return struct.pack(">5I", h0, h1, h2, h3, h4)
