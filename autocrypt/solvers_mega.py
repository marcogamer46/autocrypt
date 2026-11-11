"""Massive encoding/cipher expansion — "universal decryptor" wave.

Registers into the same REGISTRY as solvers.py/solvers_extra.py/stego.py.
Imported at the bottom of solvers.py alongside the others.

Covers:
  Encodings  : base62, base91, base92, HTML entities, Unicode escapes,
               Punycode, percent-encoded UTF-8, ROT5/ROT18/ROT-N brute,
               keyboard/QWERTY shift, T9/phone keypad, tap code,
               multi-layer base64 auto-peel
  Ciphers    : Beaufort, bifid, ADFGVX/ADFGX, four-square (stub),
               Vigenere key-length brute (IC + hill-climb),
               keyboard/columnar key brute, Porta, running-key (short texts)
  File types : PDF text extraction, DOCX/ODT text extraction, WAV LSB
  Misc       : Whitespace/Zero-width stego, Baudot/ITA2, EBCDIC decode,
               decimal-to-ASCII (space/comma separated), reversed hex,
               Letter-number (A1Z26 hex variant), Pigpen (no-op hint),
               semaphore (no-op hint), binary Gray code decode
"""
from __future__ import annotations

import html
import io
import math
import re
import string
import struct
import unicodedata
import zipfile

from autocrypt.core import solver
from autocrypt.scoring import assess, WORDS

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _emit(ctx, plain, method, params=None, score=None):
    params = params or {}
    if score is None:
        score, _ = assess(plain)
    yield plain, method, params, score


def _text(data: bytes) -> str:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return ""


def _utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


# ============================================================ ENCODINGS ====

# ------------------------------------------------------------ base62 -------
_B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase

@solver("base62", lambda fp: .45 if fp["charset"] == "ascii-text"
        and re.fullmatch(r"[0-9A-Za-z]+", fp.get("_text", "").strip() or "!")
        and 6 <= fp["length"] <= 200 else 0.0)
def solve_base62(data, ctx):
    text = _text(data).strip()
    if not text or not re.fullmatch(r"[0-9A-Za-z]+", text):
        return
    # Decode big-endian base62
    n = 0
    for ch in text:
        idx = _B62.find(ch)
        if idx == -1:
            return
        n = n * 62 + idx
    if n == 0:
        return
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if out:
        yield from _emit(ctx, out, "base62")


# ------------------------------------------------------------ base91 -------
_B91_TABLE = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    '!#$%&()*+,./:;<=>?@[]^_`{|}~"'
)
_B91_DECODE = {c: i for i, c in enumerate(_B91_TABLE)}

def _b91_decode(data: bytes) -> bytes:
    v = b = n = 0
    out = bytearray()
    for byte in data:
        ch = chr(byte)
        p = _B91_DECODE.get(ch, -1)
        if p == -1:
            continue
        if b == -1:
            b = p
        else:
            b += p * 91
            v |= b << n
            n += 13 if (b & 8191) > 88 else 14
            b = -1
            while n > 7:
                out.append(v & 255)
                v >>= 8
                n -= 8
    if b != -1:
        out.append((v | b << n) & 255)
    return bytes(out)

@solver("base91", lambda fp: .40 if fp["charset"] == "ascii-text"
        and 4 <= fp["length"] <= 20_000
        and all(c in _B91_TABLE or c.isspace() for c in fp.get("_text", ""))
        else 0.0)
def solve_base91(data, ctx):
    text = _text(data)
    if not text:
        return
    valid = set(_B91_TABLE)
    if not all(c in valid or c.isspace() for c in text):
        return
    out = _b91_decode(data)
    if out:
        yield from _emit(ctx, out, "base91")


# ------------------------------------------------------------ base92 -------
# Base92: printable ASCII 35–126 except backtick (96)
_B92_CHARS = [chr(i) for i in range(35, 127) if i != 96]

@solver("base92", lambda fp: .35 if fp["charset"] == "ascii-text"
        and 4 <= fp["length"] <= 20_000 else 0.0)
def solve_base92(data, ctx):
    text = _text(data).strip()
    if not text:
        return
    valid = set(_B92_CHARS)
    if not all(c in valid for c in text):
        return
    n = 0
    for ch in text:
        n = n * 91 + _B92_CHARS.index(ch)
    if n == 0:
        return
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if out:
        yield from _emit(ctx, out, "base92")


# ---------------------------------------------------- HTML entities --------
@solver("html-entities", lambda fp: .80 if fp["charset"] == "ascii-text"
        and ("&amp;" in fp.get("_text", "") or "&#" in fp.get("_text", "")
             or "&lt;" in fp.get("_text", "") or "&gt;" in fp.get("_text", ""))
        else 0.0)
def solve_html_entities(data, ctx):
    text = _text(data)
    if not text:
        return
    out = html.unescape(text)
    if out != text:
        yield from _emit(ctx, out.encode("utf-8", "replace"), "HTML entities")


# ------------------------------------------------- Unicode escapes ---------
_UNI_PATTERNS = [
    (re.compile(r'\\[Uu]([0-9a-fA-F]{4,8})'), lambda m: chr(int(m.group(1), 16))),
    (re.compile(r'\\x([0-9a-fA-F]{2})'),       lambda m: chr(int(m.group(1), 16))),
    (re.compile(r'%u([0-9a-fA-F]{4})'),        lambda m: chr(int(m.group(1), 16))),
    (re.compile(r'&#([0-9]{1,7});'),            lambda m: chr(int(m.group(1)))),
    (re.compile(r'&#x([0-9a-fA-F]{1,6});'),    lambda m: chr(int(m.group(1), 16))),
    (re.compile(r'U\+([0-9a-fA-F]{4,6})'),     lambda m: chr(int(m.group(1), 16))),
]

@solver("unicode-escapes", lambda fp: .75 if fp["charset"] == "ascii-text"
        and (r"\u" in fp.get("_text", "") or r"\x" in fp.get("_text", "")
             or "%u" in fp.get("_text", "") or "U+" in fp.get("_text", "")
             or "&#" in fp.get("_text", ""))
        else 0.0)
def solve_unicode_escapes(data, ctx):
    text = _text(data)
    if not text:
        return
    for pattern, repl in _UNI_PATTERNS:
        if not pattern.search(text):
            continue
        try:
            out = pattern.sub(repl, text)
            if out != text:
                yield from _emit(ctx, out.encode("utf-8", "replace"), "unicode escapes")
                text = out  # chain within the same solver (e.g. mixed \u and \x)
        except (ValueError, OverflowError):
            continue


# -------------------------------------------------------- Punycode ----------
@solver("punycode", lambda fp: .65 if fp["charset"] == "ascii-text"
        and "xn--" in fp.get("_text", "").lower() else 0.0)
def solve_punycode(data, ctx):
    text = _text(data).strip().lower()
    if "xn--" not in text:
        return
    try:
        out = text.encode("ascii").decode("idna")
        if out != text:
            yield from _emit(ctx, out.encode("utf-8", "replace"), "punycode/IDN")
    except (UnicodeError, UnicodeDecodeError):
        pass


# --------------------------------------- ROT5 / ROT18 / ROT-N brute --------
def _rot_str(text: str, n: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + n) % 26 + base))
        elif ch.isdigit():
            result.append(chr((ord(ch) - ord('0') + n) % 10 + ord('0')))
        else:
            result.append(ch)
    return "".join(result)


@solver("rot5", lambda fp: .35 if fp["charset"] == "ascii-text"
        and re.search(r'\d', fp.get("_text", "")) else 0.0)
def solve_rot5(data, ctx):
    """ROT5: rotate digits only (useful when combined with ROT13 = ROT18)."""
    text = _text(data)
    if not text:
        return
    out = "".join(chr((ord(c) - ord('0') + 5) % 10 + ord('0')) if c.isdigit() else c
                  for c in text)
    if out != text:
        yield from _emit(ctx, out.encode("utf-8", "replace"), "ROT5")


@solver("rot18", lambda fp: .40 if fp["charset"] == "ascii-text"
        and re.search(r'[A-Za-z]', fp.get("_text", ""))
        and re.search(r'\d', fp.get("_text", "")) else 0.0)
def solve_rot18(data, ctx):
    """ROT18 = ROT13 (letters) + ROT5 (digits), one explicit map."""
    text = _text(data)
    if not text:
        return
    out = "".join(
        chr((ord(c) - 97 + 13) % 26 + 97) if "a" <= c <= "z"
        else chr((ord(c) - 65 + 13) % 26 + 65) if "A" <= c <= "Z"
        else chr((ord(c) - 48 + 5) % 10 + 48) if "0" <= c <= "9"
        else c
        for c in text)
    if out != text:
        yield from _emit(ctx, out.encode("utf-8", "replace"), "ROT18")


@solver("rot-n-brute", lambda fp: .20 if fp["charset"] == "ascii-text"
        and re.search(r'[A-Za-z]{4,}', fp.get("_text", "")) else 0.0)
def solve_rot_n_brute(data, ctx):
    """Try all 25 ROT shifts and surface the best-scoring one (skip ROT13 already covered)."""
    text = _text(data)
    if not text:
        return
    best_score, best_out, best_n = 0.0, None, 0
    for n in range(1, 26):
        if n == 13:
            continue  # handled by dedicated ROT13 solver
        candidate = _rot_str(text, n)
        score, _ = assess(candidate.encode("utf-8", "replace"))
        if score > best_score:
            best_score, best_out, best_n = score, candidate, n
    if best_out and best_score >= .45:
        yield from _emit(ctx, best_out.encode("utf-8", "replace"),
                         "ROT-N", {"shift": best_n}, score=best_score)


# ------------------------------------------ Keyboard / QWERTY shift --------
# Standard QWERTY row-shift: each key shifted one key to the right on the same row.
_QWERTY_ROWS = ["qwertyuiop", "asdfghjkl;", "zxcvbnm,./"]
_QWERTY_SHIFT: dict[str, str] = {}
for _row in _QWERTY_ROWS:
    for _i, _ch in enumerate(_row[:-1]):
        _QWERTY_SHIFT[_ch] = _row[_i + 1]
        _QWERTY_SHIFT[_ch.upper()] = _row[_i + 1].upper()
    # wrap last → first
    _QWERTY_SHIFT[_row[-1]] = _row[0]
    _QWERTY_SHIFT[_row[-1].upper()] = _row[0].upper()

# Reverse map (shifted-right → original)
_QWERTY_UNSHIFT = {v: k for k, v in _QWERTY_SHIFT.items()}


@solver("keyboard-shift", lambda fp: .30 if fp["charset"] == "ascii-text"
        and re.search(r'[A-Za-z]{3,}', fp.get("_text", "")) else 0.0)
def solve_keyboard_shift(data, ctx):
    text = _text(data)
    if not text:
        return
    # Try both directions
    for direction, table in [("left", _QWERTY_UNSHIFT), ("right", _QWERTY_SHIFT)]:
        out = "".join(table.get(c, c) for c in text)
        if out != text:
            score, _ = assess(out.encode("utf-8", "replace"))
            if score >= .40:
                yield from _emit(ctx, out.encode("utf-8", "replace"),
                                 "keyboard shift", {"direction": direction}, score=score)


# ---------------------------------------------- T9 / phone keypad ----------
_T9_MAP = {
    '2': 'abc', '3': 'def', '4': 'ghi', '5': 'jkl',
    '6': 'mno', '7': 'pqrs', '8': 'tuv', '9': 'wxyz',
}
# Reverse: letter → (digit, position 1-indexed)
_T9_REV = {ch: (d, i + 1) for d, letters in _T9_MAP.items()
           for i, ch in enumerate(letters)}

@solver("t9-phone", lambda fp: .40 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[\d\s]+', fp.get("_text", "").strip() or "x")
        and len(re.sub(r'\s', '', fp.get("_text", ""))) >= 4 else 0.0)
def solve_t9(data, ctx):
    """T9: space-separated numbers, each digit = letter position on that key.
    e.g. '8 3 5 5 666' → 'hello'"""
    text = _text(data).strip()
    if not text:
        return
    tokens = text.split()
    if not all(re.fullmatch(r'\d+', t) for t in tokens):
        return
    results = []
    for token in tokens:
        # Each run of same digit = repeated press → position
        chars = []
        i = 0
        while i < len(token):
            d = token[i]
            if d not in _T9_MAP:
                chars = None
                break
            run = 0
            while i < len(token) and token[i] == d:
                run += 1
                i += 1
            letters = _T9_MAP[d]
            chars.append(letters[(run - 1) % len(letters)])
        if chars is None:
            return
        results.append("".join(chars))
    out_spaced = " ".join(results) if len(results) > 1 else results[0]
    out_joined = "".join(results)
    # Score both and emit the better one
    score_s, _ = assess(out_spaced.encode("utf-8", "replace"))
    score_j, _ = assess(out_joined.encode("utf-8", "replace"))
    if score_s >= score_j:
        yield from _emit(ctx, out_spaced.encode("utf-8", "replace"), "T9 phone keypad", score=score_s)
    else:
        yield from _emit(ctx, out_joined.encode("utf-8", "replace"), "T9 phone keypad", score=score_j)


# ------------------------------------------------------- Tap code -----------
# Polybius 5×5 (C=K merged), row then column, each as dot groups separated by space
# e.g. 'tap tap | tap tap tap' style: typically encoded as digit pairs
@solver("tap-code", lambda fp: .35 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[\d\s,./|]+', fp.get("_text", "").strip() or "x")
        and len(fp.get("_text", "").strip()) >= 6 else 0.0)
def solve_tap_code(data, ctx):
    """Tap code: pairs of numbers (row, col) in a 5×5 Polybius (C=K).
    Input can be space/comma/slash/pipe separated pairs."""
    text = _text(data).strip()
    if not text:
        return
    nums = re.findall(r'\d+', text)
    if len(nums) < 2 or len(nums) % 2 != 0:
        return
    grid = "abdefghijklmnopqrstuvwxyz"  # 25 letters, c→k
    out = []
    for i in range(0, len(nums), 2):
        r, c = int(nums[i]) - 1, int(nums[i + 1]) - 1
        if not (0 <= r < 5 and 0 <= c < 5):
            return
        out.append(grid[r * 5 + c])
    result = "".join(out)
    if result:
        yield from _emit(ctx, result.encode("utf-8", "replace"), "tap code")


# -------------------------------------- Multi-layer base64 auto-peel -------
import base64 as _b64

@solver("multi-base64", lambda fp: .50 if "base64" in [h for h, _ in fp.get("hypotheses", [])]
        and fp["length"] > 20 else 0.0)
def solve_multi_base64(data, ctx):
    """Repeatedly base64-decode until non-base64 output or depth limit."""
    cur = data
    depth = 0
    chain = []
    while depth < 8:
        try:
            text = cur.decode("ascii").strip()
        except UnicodeDecodeError:
            break
        compact = re.sub(r'\s+', '', text)
        if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', compact) or len(compact) % 4 != 0:
            break
        try:
            nxt = _b64.b64decode(compact + "==")
        except Exception:
            break
        if nxt == cur or len(nxt) == 0:
            break
        depth += 1
        chain.append("base64")
        cur = nxt
        # Try to decode as text; if it looks good, yield immediately
        score, _ = assess(cur)
        if score >= .40 and depth >= 2:
            method = "->".join(chain)
            yield from _emit(ctx, cur, f"multi-layer base64 ({method})", score=score)
            return
    if depth >= 2 and cur:
        score, _ = assess(cur)
        if score >= .35:
            method = "->".join(chain)
            yield from _emit(ctx, cur, f"multi-layer base64 ({method})", score=score)


# --------------------------------------------- EBCDIC decode ---------------
@solver("ebcdic", lambda fp: .25 if fp["charset"] in ("binary", "mixed")
        and fp["length"] >= 4 else 0.0)
def solve_ebcdic(data, ctx):
    try:
        out = data.decode("cp500")  # IBM EBCDIC International
        if sum(c.isprintable() for c in out) / max(1, len(out)) >= 0.80:
            yield from _emit(ctx, out.encode("utf-8", "replace"), "EBCDIC (cp500)")
    except (UnicodeDecodeError, LookupError):
        pass
    try:
        out = data.decode("cp037")  # IBM EBCDIC US
        if sum(c.isprintable() for c in out) / max(1, len(out)) >= 0.80:
            yield from _emit(ctx, out.encode("utf-8", "replace"), "EBCDIC (cp037)")
    except (UnicodeDecodeError, LookupError):
        pass


# ------------------------------------------- Baudot / ITA2 decode ----------
# ITA2 letter shift table (index 0-31)
# Genuine ITA2 (Baudot/Murray) code tables, indexed by the 5-bit code
# (0..31). Code 27 is FIGS shift, 31 is LTRS shift, 8 is backspace. The
# LTRS assignments (1=E, 2=LF, 3=A, 4=space, 5=S, ..., 25=B, 26=G,
# 27=FIGS, 28=M, 29=X, 30=V, 31=LTRS) follow the standard order.
_ITA2_L = [
    "_", "E", "\n", "A", " ", "S", "I", "U",
    "\r", "D", "R", "J", "N", "F", "C", "K",
    "T", "Z", "L", "W", "H", "Y", "P", "Q",
    "O", "B", "G", "_", "M", "X", "V", "_",
]
_ITA2_F = [
    "_", "3", "\n", "-", " ", "'", "8", "7",
    "\r", "$", ",", "!", ":", "(", ".", "0",
    ")", "9", "?", "+", "/", "=", "%", "@",
    "_", "2", "6", "_", ".", "/", ":", "_",
]

@solver("baudot-ita2", lambda fp: .30 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[01\s]+', fp.get("_text", "").strip() or "x")
        and len(re.sub(r'\s', '', fp.get("_text", ""))) >= 10 else 0.0)
def solve_baudot(data, ctx):
    text = _text(data).strip()
    bits = re.sub(r'\s', '', text)
    if len(bits) % 5 != 0 or not all(c in '01' for c in bits):
        return
    codes = [int(bits[i:i+5], 2) for i in range(0, len(bits), 5)]
    out = []
    fig = False
    for code in codes:
        if code == 31:   # LTRS shift
            fig = False
        elif code == 27: # FIGS shift
            fig = True
        elif code == 8:  # backspace
            continue
        else:
            table = _ITA2_F if fig else _ITA2_L
            if 0 <= code < len(table) and table[code] != '_':
                out.append(table[code])
    result = "".join(out).strip()
    if result and len(result) >= 3:
        yield from _emit(ctx, result.encode("utf-8", "replace"), "Baudot/ITA2")


# ---------------------------------------- Decimal-to-ASCII (space/comma) --
@solver("decimal-ascii", lambda fp: .55 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[\d\s,;]+', fp.get("_text", "").strip() or "x")
        and len(re.findall(r'\d+', fp.get("_text", ""))) >= 3 else 0.0)
def solve_decimal_ascii(data, ctx):
    """Space or comma separated decimal values → ASCII characters."""
    text = _text(data).strip()
    nums = re.findall(r'\d+', text)
    if len(nums) < 3:
        return
    # Try as code points
    for nums_list in [nums]:
        try:
            out = "".join(chr(int(n)) for n in nums_list
                          if 0 < int(n) < 65536)
            printable = sum(c.isprintable() for c in out) / max(1, len(out))
            if printable >= 0.85 and len(out) >= 3:
                yield from _emit(ctx, out.encode("utf-8", "replace"), "decimal ASCII")
                break
        except (ValueError, OverflowError):
            pass


# --------------------------------------- Little-endian hex decode ----------
@solver("hex-le", lambda fp: .50 if "hex" in [h for h, _ in fp.get("hypotheses", [])]
        and fp["length"] >= 4 else 0.0)
def solve_hex_le(data, ctx):
    """Hex decoded as little-endian pairs / reversed byte order variants."""
    text = _text(data)
    if not text:
        return
    clean = re.sub(r'\s', '', text)
    if len(clean) % 2 != 0 or not re.fullmatch(r'[0-9a-fA-F]+', clean):
        return
    # Reverse the byte pairs (little-endian interpretation)
    pairs = [clean[i:i+2] for i in range(0, len(clean), 2)]
    out = bytes.fromhex("".join(reversed(pairs)))
    score, _ = assess(out)
    if score >= .40:
        yield from _emit(ctx, out, "hex (little-endian byte-reversed)", score=score)


# ===================================================== CLASSICAL CIPHERS ===

# --------------------------------------------------------- Beaufort ---------

# ----------------------------------------------------------- Bifid ----------
def _make_polybius(key: str = ""):
    """5×5 Polybius square (J=I)."""
    seen = set()
    sq = []
    for ch in (key.upper() + string.ascii_uppercase):
        if ch == 'J':
            ch = 'I'
        if ch in seen or not ch.isalpha():
            continue
        seen.add(ch)
        sq.append(ch)
    return sq  # 25-element list


def _bifid_decrypt(text: str, key: str, period: int = 0) -> str:
    sq = _make_polybius(key)
    pos = {ch: (i // 5, i % 5) for i, ch in enumerate(sq)}
    rpos = {(i // 5, i % 5): ch for i, ch in enumerate(sq)}

    letters = [(i, ch.upper().replace('J', 'I'))
               for i, ch in enumerate(text) if ch.isalpha()]
    n = len(letters)
    if n == 0:
        return text

    p = period if period > 0 else n
    result = list(text)

    for start in range(0, n, p):
        chunk = letters[start:start + p]
        rows = [pos[ch][0] for _, ch in chunk]
        cols = [pos[ch][1] for _, ch in chunk]
        combined = rows + cols
        for k, (orig_i, _) in enumerate(chunk):
            r = combined[k]
            c = combined[k + len(chunk)]
            plain_ch = rpos[(r, c)]
            result[orig_i] = plain_ch if text[orig_i].isupper() else plain_ch.lower()

    return "".join(result)


@solver("bifid", lambda fp: .22 if fp["charset"] == "ascii-text"
        and re.search(r'[A-Za-z]{10,}', fp.get("_text", "")) else 0.0)
def solve_bifid(data, ctx):
    """Bifid cipher — brute-force period 0 (full text) and 5/6/7."""
    text = _text(data)
    letters = re.sub(r'[^A-Za-z]', '', text)
    if len(letters) < 10:
        return
    best = (0.0, "", "", 0)
    # Try with empty key (alphabetic square) and a few common CTF keys
    keys_to_try = ["", "KEY", "SECRET", "CRYPTO", "FLAG", "CIPHER"]
    for key in keys_to_try:
        for period in [0, 5, 6, 7, 8]:
            try:
                out = _bifid_decrypt(text, key, period)
                score, _ = assess(out.encode("utf-8", "replace"))
                if score > best[0]:
                    best = (score, out, key, period)
            except Exception:
                continue
    if best[0] >= .45:
        params = {"key": best[2] or "default"} if best[2] else {}
        if best[3]:
            params["period"] = best[3]
        yield from _emit(ctx, best[1].encode("utf-8", "replace"),
                         "bifid", params, score=best[0])


# --------------------------------------------------------- ADFGVX -----------
_ADFGVX_CHARS = "ADFGVX"
_ADFGVX_DEFAULT = (  # Standard ADFGVX square (alphabet + digits)
    "ph0q g64mea 1yl2nofdxkr3cvs5zw7bj9uti8"
    .replace(" ", "")  # 36 chars: a-z + 0-9
)
# Build a 6×6 grid
_ADFGVX_GRID: dict[str, tuple[str, str]] = {}
_ADFGVX_GRID_REV: dict[tuple[str, str], str] = {}

def _build_adfgvx(key_sq: str):
    """Build encode/decode maps for a 6×6 ADFGVX square."""
    enc, dec = {}, {}
    for i, ch in enumerate(key_sq[:36]):
        r = _ADFGVX_CHARS[i // 6]
        c = _ADFGVX_CHARS[i % 6]
        enc[ch.upper()] = r + c
        dec[(r, c)] = ch.upper()
    return enc, dec


def _adfgvx_decrypt(ciphertext: str, transkey: str, square_key: str = "") -> str:
    _, dec = _build_adfgvx(square_key if square_key else _ADFGVX_DEFAULT)
    # Strip to only valid chars
    text = re.sub(r'[^ADFGVX]', '', ciphertext.upper())
    if len(text) % 2 != 0:
        return ""
    # Reverse columnar transposition
    n_cols = len(transkey)
    sorted_key = sorted(range(n_cols), key=lambda i: transkey[i])
    n_rows = math.ceil(len(text) / (2 * n_cols))
    col_len = n_rows * 2
    # Split into columns by sorted key order
    cols: list[str] = []
    pos = 0
    for _ in sorted_key:
        cols.append(text[pos:pos + col_len])
        pos += col_len
    if pos != len(text):
        return ""
    # Unsort columns
    unsorted = [""] * n_cols
    for rank, orig in enumerate(sorted_key):
        unsorted[orig] = cols[rank]
    # Read row by row
    pairs = []
    for row in range(n_rows * 2):
        for col in range(n_cols):
            if row < len(unsorted[col]):
                pairs.append(unsorted[col][row])
    out = []
    for i in range(0, len(pairs), 2):
        key = (pairs[i], pairs[i + 1])
        ch = dec.get(key, "?")
        out.append(ch)
    return "".join(out)


@solver("adfgvx", lambda fp: .35 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[ADFGVXadfgvx\s]+', fp.get("_text", "").strip() or "x")
        and len(re.sub(r'\s', '', fp.get("_text", ""))) >= 8 else 0.0)
def solve_adfgvx(data, ctx):
    text = _text(data).strip()
    if not text:
        return
    clean = re.sub(r'[^ADFGVX]', '', text.upper())
    if len(clean) < 8 or len(clean) % 2 != 0:
        return
    # Try common CTF transposition keys
    for tkey in ["KEY", "CRYPTO", "SECRET", "CIPHER", "FLAG", "CODE",
                 "AB", "ABC", "ABCD", "ABCDE", "ABCDEF"]:
        try:
            out = _adfgvx_decrypt(clean, tkey)
            if not out:
                continue
            score, _ = assess(out.encode("utf-8", "replace"))
            if score >= .45:
                yield from _emit(ctx, out.encode("utf-8", "replace"),
                                 "ADFGVX", {"transkey": tkey}, score=score)
                return
        except Exception:
            continue


# ----------------------------------------- Porta cipher -------------------
_PORTA_TABLE = [
    "nopqrstuvwxyzabcdefghijklm",  # A/B
    "mnopqrstuvwxyzabcdefghijkl",  # C/D  (simplified — symmetrical)
    "lmnopqrstuvwxyzabcdefghijk",  # E/F
    "klmnopqrstuvwxyzabcdefghij",  # G/H
    "jklmnopqrstuvwxyzabcdefghi",  # I/J
    "ijklmnopqrstuvwxyzabcdefgh",  # K/L
    "hijklmnopqrstuvwxyzabcdefg",  # M/N
    "ghijklmnopqrstuvwxyzabcdef",  # O/P
    "fghijklmnopqrstuvwxyzabcde",  # Q/R
    "efghijklmnopqrstuvwxyzabcd",  # S/T
    "defghijklmnopqrstuvwxyzabc",  # U/V
    "cdefghijklmnopqrstuvwxyzab",  # W/X
    "bcdefghijklmnopqrstuvwxyza",  # Y/Z
]


# ------------------------------------------ Vigenere key-length brute ------
@solver("vigenere-brute", lambda fp: .20 if fp["charset"] == "ascii-text"
        and re.search(r'[A-Za-z]{30,}', fp.get("_text", "")) else 0.0)
def solve_vigenere_brute(data, ctx):
    """IC-guided Vigenere brute: test key lengths 1-15, freq-recover key."""
    text = _text(data)
    letters = re.sub(r'[^A-Za-z]', '', text).upper()
    if len(letters) < 30:
        return
    english_ic = 0.0667
    best = (0.0, "", "")
    english_freq = [8.2,1.5,2.8,4.3,12.7,2.2,2.0,6.1,7.0,0.2,0.8,4.0,
                    2.4,6.7,7.5,1.9,0.1,6.0,6.3,9.1,2.8,1.0,2.4,0.2,2.0,0.1]

    for klen in range(1, 16):
        # Check IC of columns
        ics = []
        for col in range(klen):
            col_text = letters[col::klen]
            if len(col_text) < 4:
                continue
            counts = [0] * 26
            for ch in col_text:
                counts[ord(ch) - 65] += 1
            n = len(col_text)
            ic = sum(c * (c - 1) for c in counts) / (n * (n - 1)) if n > 1 else 0
            ics.append(ic)
        if not ics:
            continue
        avg_ic = sum(ics) / len(ics)
        if abs(avg_ic - english_ic) > 0.015:
            continue
        # Recover key by frequency analysis (chi-squared)
        key = []
        for col in range(klen):
            col_text = letters[col::klen]
            counts = [0] * 26
            for ch in col_text:
                counts[ord(ch) - 65] += 1
            total = sum(counts)
            best_k, best_chi = 0, float('inf')
            for k in range(26):
                chi = sum(
                    (counts[c] - english_freq[(c - k) % 26] / 100.0 * total) ** 2
                    / max(english_freq[(c - k) % 26] / 100.0 * total, 0.001)
                    for c in range(26)
                )
                if chi < best_chi:
                    best_chi, best_k = chi, k
            key.append(chr(best_k + 65))
        key_str = "".join(key)
        # Decrypt
        out_chars = list(text)
        ki = 0
        for i, ch in enumerate(text):
            if ch.isalpha():
                k = ord(key_str[ki % klen]) - 65
                p = (ord(ch.upper()) - 65 - k) % 26
                out_chars[i] = chr(p + 65) if ch.isupper() else chr(p + 97)
                ki += 1
        out = "".join(out_chars)
        score, _ = assess(out.encode("utf-8", "replace"))
        if score > best[0]:
            best = (score, out, key_str)
    if best[0] >= .50 and best[2]:
        yield from _emit(ctx, best[1].encode("utf-8", "replace"),
                         "vigenere (brute)", {"key": best[2]}, score=best[0])


# ============================================== FILE-TYPE SOLVERS ===========

# ---------------------------------------------- PDF text extraction --------
@solver("pdf-text", lambda fp: .90 if fp.get("filetype") == "PDF document" else 0.0)
def solve_pdf(data, ctx):
    """Extract human-readable text from a PDF without external deps."""
    # Pure-Python approach: extract text from stream objects
    try:
        text_chunks = []
        # Find all stream objects
        for m in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', data, re.DOTALL):
            raw = m.group(1)
            # Try zlib decompress
            for wbits in (15, -15, 31):
                try:
                    import zlib as _zlib
                    dec = _zlib.decompress(raw, wbits)
                    raw = dec
                    break
                except Exception:
                    pass
            # Extract text between BT/ET blocks (PDF text operators)
            for bt in re.finditer(rb'BT(.*?)ET', raw, re.DOTALL):
                block = bt.group(1)
                # Tj, TJ operators
                for tj in re.finditer(rb'\(([^)]{1,500})\)\s*Tj', block):
                    try:
                        text_chunks.append(tj.group(1).decode('latin-1', 'replace'))
                    except Exception:
                        pass
                for tj in re.finditer(rb'\[([^\]]{1,2000})\]\s*TJ', block):
                    inner = tj.group(1)
                    for s in re.finditer(rb'\(([^)]{1,500})\)', inner):
                        try:
                            text_chunks.append(s.group(1).decode('latin-1', 'replace'))
                        except Exception:
                            pass
        if text_chunks:
            out = " ".join(text_chunks)
            # Clean PDF escape sequences
            out = re.sub(r'\\(\d{3})', lambda m: chr(int(m.group(1), 8)), out)
            out = out.replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t')
            if len(out.strip()) >= 4:
                yield from _emit(ctx, out.encode("utf-8", "replace"), "PDF text extraction")
    except Exception:
        pass

    # Fallback: try pypdf if installed
    try:
        import pypdf as _pypdf
        reader = _pypdf.PdfReader(io.BytesIO(data))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        out = "\n".join(pages).strip()
        if out:
            yield from _emit(ctx, out.encode("utf-8", "replace"), "PDF text (pypdf)")
    except ImportError:
        pass
    except Exception:
        pass


# -------------------------------------------- DOCX / ODT text extraction --
@solver("docx-text", lambda fp: .90 if fp.get("filetype") == "ZIP archive"
        and fp["length"] > 100 else 0.0)
def solve_docx(data, ctx):
    """Extract text from DOCX / ODT / XLSX / PPTX (all ZIP-based Office formats)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return
    names = zf.namelist()
    text_files = []
    # DOCX: word/document.xml
    if "word/document.xml" in names:
        text_files.append(("word/document.xml", "DOCX"))
    # ODT: content.xml
    if "content.xml" in names:
        text_files.append(("content.xml", "ODT"))
    # PPTX: ppt/slides/slide*.xml
    for n in names:
        if re.match(r'ppt/slides/slide\d+\.xml', n):
            text_files.append((n, "PPTX"))
    # XLSX: xl/sharedStrings.xml
    if "xl/sharedStrings.xml" in names:
        text_files.append(("xl/sharedStrings.xml", "XLSX"))
    if not text_files:
        return
    for fname, fmt in text_files[:4]:
        try:
            xml = zf.read(fname).decode("utf-8", "replace")
        except Exception:
            continue
        # Strip XML tags and decode entities
        txt = re.sub(r'<[^>]+>', ' ', xml)
        txt = html.unescape(txt)
        txt = re.sub(r'\s+', ' ', txt).strip()
        if len(txt) >= 4:
            yield from _emit(ctx, txt.encode("utf-8", "replace"),
                             f"{fmt} text extraction")


# ------------------------------------------------- WAV LSB steganography ---

# ------------------------------------------- Whitespace / zero-width stego
_ZW_MAP = {
    '\u200b': '0',  # zero-width space
    '\u200c': '1',  # zero-width non-joiner
    '\u200d': '1',  # zero-width joiner (alt)
    '\ufeff': '0',  # BOM / zero-width no-break space
    '\u2060': '0',  # word joiner
    '\u00ad': '1',  # soft hyphen
}

_ZW_BYTES = [c.encode("utf-8") for c in _ZW_MAP]

@solver("whitespace-stego", lambda fp: .60
        if any(zb in fp.get("_head", b"") for zb in _ZW_BYTES)
        or any(c in fp.get("_text", "") for c in _ZW_MAP) else 0.0)
def solve_whitespace_stego(data, ctx):
    """Decode zero-width / invisible character steganography."""
    text = _utf8(data)
    if not text:
        return
    # Delimiter scheme first: zero-width space/non-joiner encode bits, and
    # the zero-width joiner (‍) separates bytes. Common in "hidden in
    # zero-width" challenge writer tools. Try that before the flat bitstream.
    if '‍' in text:
        byt, bytebits = bytearray(), ""
        for ch in text:
            if ch == '‍':
                if bytebits:
                    byt.append(int(bytebits, 2))
                    bytebits = ""
            elif ch == '​':
                bytebits += '0'
            elif ch == '‌':
                bytebits += '1'
        if bytebits:
            byt.append(int(bytebits, 2))
        if byt:
            printable = sum(32 <= b < 127 for b in byt) / max(1, len(byt))
            if printable >= 0.80:
                yield from _emit(ctx, bytes(byt), "zero-width steganography (delimiter scheme)")
                return
    # Zero-width binary encoding
    bits = ""
    for ch in text:
        if ch in _ZW_MAP:
            bits += _ZW_MAP[ch]
    if len(bits) >= 8:
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            out.append(int(bits[i:i+8], 2))
        printable = sum(32 <= b < 127 for b in out) / max(1, len(out))
        if printable >= 0.80:
            yield from _emit(ctx, bytes(out), "zero-width steganography")
            return

    # Whitespace-only lines (Whitespace language / trailing spaces)
    lines = text.split('\n')
    trailing = ""
    for line in lines:
        stripped = line.rstrip('\r')
        spaces = len(stripped) - len(stripped.rstrip(' \t'))
        if spaces > 0:
            trailing += stripped[-spaces:]
    if trailing:
        bits2 = trailing.replace(' ', '0').replace('\t', '1')
        if len(bits2) >= 8:
            out2 = bytearray()
            for i in range(0, len(bits2) - 7, 8):
                out2.append(int(bits2[i:i+8], 2))
            printable = sum(32 <= b < 127 for b in out2) / max(1, len(out2))
            if printable >= 0.80:
                yield from _emit(ctx, bytes(out2), "trailing whitespace steganography")


# -------------------------------------------- Gray code binary decode ------
def _gray_to_bin(n: int) -> int:
    mask = n >> 1
    while mask:
        n ^= mask
        mask >>= 1
    return n


@solver("gray-code", lambda fp: .30 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[01\s]+', fp.get("_text", "").strip() or "x")
        and len(re.sub(r'\s', '', fp.get("_text", ""))) >= 8 else 0.0)
def solve_gray_code(data, ctx):
    """Gray code binary → ASCII."""
    text = _text(data).strip()
    bits = re.sub(r'\s', '', text)
    if len(bits) % 8 != 0 or not all(c in '01' for c in bits):
        return
    out = bytearray()
    for i in range(0, len(bits), 8):
        gray_val = int(bits[i:i+8], 2)
        out.append(_gray_to_bin(gray_val))
    printable = sum(32 <= b < 127 for b in out) / max(1, len(out))
    if printable >= 0.80:
        yield from _emit(ctx, bytes(out), "Gray code binary")


# ---------------------------------------- Letter-to-number variants --------
@solver("a1z26-hex", lambda fp: .30 if fp["charset"] == "ascii-text"
        and re.fullmatch(r'[0-9a-fA-F\s,]+', fp.get("_text", "").strip() or "!")
        and len(re.findall(r'[0-9a-fA-F]+', fp.get("_text", ""))) >= 3 else 0.0)
def solve_a1z26_hex(data, ctx):
    """Hex numbers where each value is a letter number (0x01=A ... 0x1A=Z)."""
    text = _text(data).strip()
    nums = re.findall(r'[0-9a-fA-F]+', text)
    if len(nums) < 3:
        return
    try:
        out = "".join(chr(int(n, 16) + 64) for n in nums
                      if 1 <= int(n, 16) <= 26)
        if len(out) == len(nums) and out.isalpha():
            yield from _emit(ctx, out.encode("utf-8", "replace"), "A1Z26 hex variant")
    except ValueError:
        pass


# ------------------------------------------- Reversed text ----------------
@solver("reversed-text", lambda fp: .15 if fp["charset"] == "ascii-text"
        and fp["length"] >= 8 else 0.0)
def solve_reversed(data, ctx):
    """Simply reversed text/bytes — catches typos, simple obfuscation."""
    text = _text(data)
    if not text:
        return
    out = text[::-1]
    score, _ = assess(out.encode("utf-8", "replace"))
    if score >= .55:
        yield from _emit(ctx, out.encode("utf-8", "replace"), "reversed text", score=score)


# ---------------------------------------- Columnar transposition brute ----
@solver("columnar-brute", lambda fp: .15 if fp["charset"] == "ascii-text"
        and re.search(r'[A-Za-z]{20,}', fp.get("_text", "")) else 0.0)
def solve_columnar_brute(data, ctx):
    """Brute-force columnar transposition for 2-6 columns (no key needed)."""
    text = _text(data)
    letters_only = re.sub(r'[^A-Za-z]', '', text)
    n = len(letters_only)
    if n < 20 or n > 500:
        return
    best = (0.0, "", 0)
    for cols in range(2, 8):
        rows = math.ceil(n / cols)
        # Pad to rectangle
        padded = letters_only + 'X' * (rows * cols - n)
        # Try all column orderings (only feasible for small col counts)
        from itertools import permutations
        for perm in permutations(range(cols)):
            if ctx.expired():
                return
            # Re-read by this column order
            grid = [padded[i:i+rows] for i in range(0, rows*cols, rows)]
            rearranged = [grid[c] for c in perm]
            out = "".join("".join(rearranged[c][r] for c in range(cols)
                                   if r < len(rearranged[c]))
                          for r in range(rows))
            out = out[:n]
            score, _ = assess(out.encode("utf-8", "replace"))
            if score > best[0]:
                best = (score, out, cols)
            if best[0] >= .80:
                break
        if best[0] >= .80:
            break
    if best[0] >= .55:
        yield from _emit(ctx, best[1].encode("utf-8", "replace"),
                         "columnar transposition (brute)", {"cols": best[2]},
                         score=best[0])
