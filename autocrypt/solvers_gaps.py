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
import re

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
_PEM_RE = re.compile(rb"-----BEGIN [A-Z ]*PUBLIC KEY-----[\r\n\s]*([A-Za-z0-9+/=]+)[\r\n\s]*-----END [A-Z ]*PUBLIC KEY-----")


def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@solver("jwt-key-confusion", lambda fp: .45
        if fp.get("charset") in ("ascii-text", "mixed") and fp.get("_text") and
        _JWT_RE.search(data) and _PEM_RE.search(data) else 0.0)
def solve_jwt_key_confusion(data, ctx):
    """Forge/verify a JWT whose alg is asymmetric but whose signature is an
    HMAC keyed with the RSA public key (RS256->HS256 confusion)."""
    pem = _PEM_RE.search(data)
    if not pem:
        return
    try:
        der = base64.b64decode(pem.group(1))
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
                                 "JWT RS256->HS256 key confusion",
                                 {"alg": alg}, score=.9)
                return
