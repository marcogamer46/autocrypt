"""Pack 3: p+q leak, 2-symbol alphabets, Braille, DNA, base32hex/Crockford/swapped base64,
byte-level transforms (ROL/ROR/add/sub/nibble/bit-reverse), RC4 and AES/Fernet with a given key."""
from __future__ import annotations
import base64
import hashlib
import math
import re
import string

from core import solver
from scoring import assess, plain_text_score
import solvers as S
from solvers_more import _vals, _pick, _txt


def _bits_to_bytes(bits, n=8):
    return bytes(int(bits[i:i + n], 2) for i in range(0, len(bits) - n + 1, n))


def _printable(b, lim=.95):
    return len(b) > 0 and sum(32 <= x < 127 or x in (9, 10, 13) for x in b) / len(b) >= lim


# ------------------------------------------------ RSA with p+q / p-q leak
@solver("RSA-sum-leak", lambda fp: .999 if fp["charset"] == "ascii-text" and re.search(
    r"\b(?:p_?plus_?q|sum_?pq|p\+q|pq_sum|s|x)\s*=", fp.get("_text", "")) else 0.0)
def solve_sum_leak(data, ctx):
    v = _vals(data, ctx)
    n, c, e = v.get("n"), _pick(v, "c", "ct", "enc", "cyphertext", "ciphertext"), v.get("e", 65537)
    s = _pick(v, "p_plus_q", "pplusq", "sum_pq", "pq_sum", "s", "x")
    if not (n and c and s):
        return
    disc = s * s - 4 * n
    r = math.isqrt(disc) if disc >= 0 else -1
    if r >= 0 and r * r == disc:
        p, q = (s + r) // 2, (s - r) // 2
        if p * q == n and math.gcd(e, (p - 1) * (q - 1)) == 1:
            pl = S._int_plain(pow(c, pow(e, -1, (p - 1) * (q - 1)), n))
            yield pl, "RSA known p+q", {"_statistical": True}, .98


# ------------------------------------------------ generic 2-symbol alphabet
@solver("two-symbol-binary", lambda fp: .45 if fp["charset"] == "ascii-text" and len(
    set(re.sub(r"\s", "", fp.get("_text", "")))) == 2 and len(re.sub(r"\s", "", fp.get("_text", ""))) >= 16
    and not re.fullmatch(r"[01\s]+", fp.get("_text", "") or "-") else 0.0)
def solve_two_symbol(data, ctx):
    t = re.sub(r"\s", "", _txt(data))
    syms = sorted(set(t))
    if len(syms) != 2:
        return
    for a, b in ((syms[0], syms[1]), (syms[1], syms[0])):
        bits = t.replace(a, "0").replace(b, "1")
        for w in (8, 7):
            out = _bits_to_bytes(bits, w)
            if _printable(out, .9):
                yield out, f"two-symbol binary ({a}=0,{b}=1,{w}-bit)", {}, assess(out)[0]


# ------------------------------------------------ DNA codons / 2-bit
@solver("dna-2bit", lambda fp: .4 if fp["charset"] == "ascii-text" and re.fullmatch(
    r"[ACGTacgt\s]{16,}", fp.get("_text", "") or "-") else 0.0)
def solve_dna(data, ctx):
    t = re.sub(r"\s", "", _txt(data)).upper()
    import itertools
    seen = set()
    for perm in itertools.permutations("0123", 4):
        m = dict(zip("ACGT", ("00", "01", "10", "11")))
        m = {k: format(int(p), "02b") for k, p in zip("ACGT", perm)}
        out = _bits_to_bytes("".join(m[ch] for ch in t))
        if out not in seen and _printable(out, .9):
            seen.add(out)
            yield out, f"DNA 2-bit ({''.join(perm)})", {}, assess(out)[0]


# ------------------------------------------------ Braille
# One Unicode braille cell per printable ASCII character: cell n (0x2800+n)
# maps to chr(32+n). Full printable-ASCII coverage (space + 94 glyphs) so any
# flag body -- including braces, underscore, digits -- round-trips.
_BRAILLE = "".join(chr(32 + i) for i in range(95))


@solver("braille", lambda fp: .6 if any(0x2800 <= ord(c) <= 0x28FF for c in fp.get("_head", b"").decode(
    "utf-8", "ignore")) else 0.0)
def solve_braille(data, ctx):
    try:
        t = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    out = "".join(_BRAILLE[ord(c) - 0x2800] if 0x2800 <= ord(c) < 0x285F else c for c in t)
    yield out.lower().encode(), "braille", {"_statistical": True}, .99


# ------------------------------------------------ base32hex / Crockford / swapped-case base64
@solver("base-variants", lambda fp: .35 if fp["charset"] == "ascii-text" and re.fullmatch(
    r"[A-Za-z0-9+/=\s]{8,}", fp.get("_text", "") or "-") else 0.0)
def solve_base_variants(data, ctx):
    t = re.sub(r"\s", "", _txt(data))
    tries = []
    try:
        tries.append(("base32hex", base64.b32hexdecode(t.upper() + "=" * (-len(t) % 8))))
    except Exception:
        pass
    ck = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    u = t.upper().replace("O", "0").replace("I", "1").replace("L", "1")
    if u and all(c in ck for c in u):
        n = 0
        for c in u:
            n = n * 32 + ck.index(c)
        tries.append(("crockford-base32", n.to_bytes((n.bit_length() + 7) // 8, "big")))
    try:
        tries.append(("base64-swapcase", base64.b64decode(t.swapcase() + "=" * (-len(t) % 4))))
    except Exception:
        pass
    try:
        tries.append(("base64-reversed", base64.b64decode(t[::-1] + "=" * (-len(t) % 4))))
    except Exception:
        pass
    for name, out in tries:
        if out and _printable(out, .85):
            yield out, name, {}, assess(out)[0]


# ------------------------------------------------ New-Caesar (picoCTF)
# Custom cipher: b16_encode maps each byte to two nibbles, each nibble an
# index into ALPHABET = "abcdefghijklmnop" (first 16 lowercase). Each char is
# then Caesar-shifted by a single key char (mod 16). The ciphertext is purely
# [a-p] and has even length. Brute force the 16 possible shifts and take the
# highest-scoring plaintext.
@solver("new-caesar-b16", lambda fp: .55 if fp["charset"] == "ascii-text" and (
    len(re.findall(r"(?i)[a-p]{16,}", fp.get("_text", ""))) >= 1) else 0.0)
def solve_new_caesar(data, ctx):
    # Use the longest contiguous [a-p] run (the actual ciphertext). Simple
    # filtering can accidentally splice letters from hint lines like
    # "key_bytes=0x62" (k/e/b are all in a-p) into the nibble stream.
    runs = re.findall(r"(?i)[a-p]+", _txt(data))
    t = max(runs, key=len) if runs else ""
    if len(t) < 16 or len(t) % 2 != 0:
        return
    ALPHABET = string.ascii_lowercase[:16]
    best = None
    for k in range(16):                      # key offset 0..15
        idx = [((ord(c) - 97 - k) % 16) for c in t]
        try:
            out = bytes((idx[i] << 4) | idx[i + 1] for i in range(0, len(idx), 2))
        except Exception:
            continue
        pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / len(out)
        if pr < .85:
            continue
        ac = assess(out)[0]
        if best is None or ac > best[0]:
            best = (ac, out, k)
    if best:
        ac, out, k = best
        yield out, f"New-Caesar b16 (key=chr({97+k}))", {"_statistical": True}, max(.7, min(.99, ac))


# ------------------------------------------------ byte-level transforms
@solver("byte-transforms", lambda fp: .3 if fp["length"] >= 8 else 0.0)
def solve_byte_transforms(data, ctx):
    """rol/ror/add/sub by k, nibble swap, bit reverse — scored by plaintext model."""
    raw = data
    if ctx.depth > 2 or len(raw) < 8 or len(raw) > 100_000 or _printable(raw, .9):
        return   # already readable text: byte tricks would only create noise
    rev = lambda b: int(f"{b:08b}"[::-1], 2)
    cands = [("nibble-swap", bytes(((b << 4) | (b >> 4)) & 255 for b in raw)),
             ("bit-reverse", bytes(rev(b) for b in raw))]
    for k in range(1, 8):
        cands.append((f"rol{k}", bytes(((b << k) | (b >> (8 - k))) & 255 for b in raw)))
    for k in range(1, 256):
        cands.append((f"sub{k}", bytes((b - k) & 255 for b in raw)))
    scored = sorted(((plain_text_score(o), n, o) for n, o in cands if _printable(o, .9)), reverse=True)
    for i, (sc, n, o) in enumerate(scored[:3]):
        yield o, f"byte-transform({n})", {"_statistical": i == 0}, max(.5, min(.95, .6 + sc / 20)) if i == 0 else .4


# ------------------------------------------------ RC4 with key
def _rc4(key, data):
    S_ = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S_[i] + key[i % len(key)]) & 255
        S_[i], S_[j] = S_[j], S_[i]
    i = j = 0
    out = bytearray()
    for ch in data:
        i = (i + 1) & 255
        j = (j + S_[i]) & 255
        S_[i], S_[j] = S_[j], S_[i]
        out.append(ch ^ S_[(S_[i] + S_[j]) & 255])
    return bytes(out)


def _blob(v, t):
    """ciphertext bytes from labeled hex/base64 field or the whole input."""
    m = re.search(r"\b(?:ct|enc|cipher\w*|cyphertext|data|msg|message)\s*[:=]\s*['\"]?([0-9a-fA-F]{8,}|[A-Za-z0-9+/=]{12,})", t)
    s = m.group(1) if m else re.sub(r"\s", "", t)
    try:
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
            return bytes.fromhex(s)
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return b""


def _keys(t, ctx):
    ks = []
    for m in re.finditer(r"\bkey\s*[:=]\s*['\"]?([^\s'\"]+)", t, re.I):
        k = m.group(1)
        ks.append(k.encode())
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", k):
            ks.append(bytes.fromhex(k))
    for w in (ctx.wordlist or [])[:20000]:
        ks.append(w if isinstance(w, bytes) else w.encode())
    ks += [b"key", b"secret", b"password", b"flag", b"ctf", b"rc4", b"admin", b"root", b"picoctf"]
    return list(dict.fromkeys(ks))


@solver("rc4", lambda fp: .5 if fp["charset"] in ("ascii-text", "binary", "mixed") and fp["length"] >= 8 else 0.0)
def solve_rc4(data, ctx):
    t = _txt(data)
    raw = _blob({}, t) if t else data
    if not raw:
        return
    has_label = bool(re.search(r"\bkey\s*[:=]", t, re.I))
    for k in _keys(t, ctx):
        if ctx.expired():
            return
        out = _rc4(k, raw)
        if _printable(out, .97) and len(out) >= 6:
            yield out, f"Cracked RC4 (key={k[:20]!r})", {"_statistical": True}, .98 if has_label else .9
            return


# ------------------------------------------------ AES / Fernet with known key
@solver("aes-known-key", lambda fp: .9 if fp["charset"] == "ascii-text" and re.search(
    r"\bkey\s*[:=]", fp.get("_text", ""), re.I) else 0.0)
def solve_aes(data, ctx):
    t = _txt(data)
    v = {}
    for k, x in re.findall(r"\b(key|iv|nonce|ct|enc|cipher\w*|token)\s*[:=]\s*['\"]?([^\s'\",]+)", t, re.I):
        v.setdefault(k.lower(), x)
    if "key" not in v:
        return
    kraw = v["key"]
    keys = [kraw.encode()]
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", kraw):
        keys.insert(0, bytes.fromhex(kraw))
    keys += [hashlib.md5(kraw.encode()).digest(), hashlib.sha256(kraw.encode()).digest()]
    # Fernet token
    tok = v.get("token") or next((x for k, x in v.items() if k != "key" and x.startswith("gAAAA")), None)
    if tok:
        try:
            from cryptography.fernet import Fernet
            out = Fernet(kraw.encode()).decrypt(tok.encode())
            yield out, "Cracked Fernet", {"_statistical": True}, .98
            return
        except Exception:
            pass
    ctb = _blob(v, t.replace(f"key={kraw}", ""))
    iv = v.get("iv") or v.get("nonce")
    ivs = [bytes.fromhex(iv)] if iv and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", iv) else ([iv.encode()] if iv else [])
    try:
        from Crypto.Cipher import AES
    except ImportError:
        ctx.findings.append("aes-known-key: install pycryptodome (pip install pycryptodome) to decrypt")
        return
    for key in keys:
        if len(key) not in (16, 24, 32) or not ctb:
            continue
        modes = [("ECB", lambda: AES.new(key, AES.MODE_ECB))]
        for ivb in ivs or [ctb[:16]]:
            modes += [("CBC", lambda i=ivb: AES.new(key, AES.MODE_CBC, i[:16])),
                      ("CFB", lambda i=ivb: AES.new(key, AES.MODE_CFB, i[:16])),
                      ("OFB", lambda i=ivb: AES.new(key, AES.MODE_OFB, i[:16])),
                      ("CTR", lambda i=ivb: AES.new(key, AES.MODE_CTR, nonce=i[:8]))]
        for name, mk in modes:
            try:
                src = ctb if name == "ECB" or ivs else ctb[16:]
                out = mk().decrypt(src[:len(src) // 16 * 16] if name in ("ECB", "CBC") else src)
            except Exception:
                continue
            if out and out[-1] <= 16 and name in ("ECB", "CBC"):
                out = out[:-out[-1]] if out[-out[-1]:] == bytes([out[-1]]) * out[-1] else out
            if _printable(out, .95):
                yield out, f"Cracked AES-{name}", {"_statistical": True}, .98
                return
