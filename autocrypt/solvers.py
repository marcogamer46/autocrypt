"""Built-in encodings, classical ciphers, XOR, RSA, and hash/JWT solvers."""
from __future__ import annotations

import base64
import binascii
import bisect
import bz2
import collections
import gzip
import hashlib
import hmac
import importlib
import itertools
import json
import math
import multiprocessing as mp
import os
import random
import re
import string
import time
import urllib.parse
import zlib

from autocrypt.core import solver
from autocrypt.scoring import (assess, quadgram_score, quadgram_log, word_initial_log,
                     word_final_log, WORDS, _COMMON, flag_plausibility,
                     english_confidence, leet_body_dict_fraction, plain_text_score,
                     dictionary_fraction, clear_english)

try:  # optional acceleration/provider
    import gmpy2
except ImportError:
    gmpy2 = None
try:
    from Crypto.Util.number import inverse as _crypto_inverse
except ImportError:
    _crypto_inverse = None
try:
    import numpy as _np
except ImportError:
    _np = None
try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None


def _prior(fp, *names, default=0.0):
    return max((fp.get("prior_map", {}).get(n, 0.0) for n in names), default=default)


def _text_prior(fp):
    if fp["charset"] != "ascii-text" or fp["length"] < 3 or fp["length"] > 10_000:
        return 0.0
    if fp["ic"] > .16:
        return 0.0
    if fp["entropy"] > 6.2:
        return 0.12
    return .57


def _xor_prior(fp):
    if not 0 < fp["length"] <= 100_000:
        return 0.0
    if fp["charset"] == "ascii-text" and fp["entropy"] < 4.3:
        return 0.0
    return .72


def _repeat_xor_prior(fp):
    if not 12 <= fp["length"] <= 100_000:
        return 0.0
    if fp["charset"] == "ascii-text":
        # Text-like blobs (English, reversed text, etc.) keep their letter
        # frequencies (IC around 0.06+); XOR ciphertext over printable bytes is
        # close to uniform (IC well below 0.05). Only the latter is worth
        # cracking as repeating-key XOR.
        if fp["ic"] >= 0.055 or fp["entropy"] < 4.2:
            return 0.0
    # Encoded blobs (base64/hex/...) are decoder territory; treating them as
    # XOR ciphertext wastes the search budget on encoding look-alikes. The
    # decoded child blob is still eligible. Exception: small encoded blobs
    # (<=64 B) are cheap to consider and cover short XOR-over-hex flags.
    if fp.get("classes") and fp["length"] > 64:
        enc = {"hex", "base64", "base64url", "base32", "binary", "octal",
               "decimal", "morse", "url", "quoted-printable"}
        if enc.intersection(fp["classes"]):
            return 0.0
    return .64


def _emit(ctx, plain, method, params=None):
    params = params or {}
    score, _ = assess(plain)
    yield plain, method, params, score


@solver("base16", lambda fp: _prior(fp, "hex"))
def solve_hex(data, ctx):
    try:
        txt = data.decode("ascii").strip()
    except UnicodeError:
        return
    try:
        out = bytes.fromhex(txt)
        if out:
            yield from _emit(ctx, out, "hex")
            return
    except (ValueError, UnicodeError):
        pass
    # Separator-tolerant form: whitespace / , : ; / 0x-prefixed hex tokens.
    # NB: gate on TOTAL hex-nibble count (even and >= 16), NOT on the number of
    # tokens — byte-payloads of odd length (e.g. a 13-byte flag) would otherwise
    # never parse.
    toks = []
    for t in re.split(r"[\s,:;]+", txt):
        t = t.strip().lower()
        if t.startswith("0x"):
            t = t[2:]
        if t and re.fullmatch(r"[0-9a-f]{1,2}", t):
            toks.append(t)
    if len(toks) >= 8:
        h = "".join(toks)
        if len(h) % 2 == 0:
            try:
                out = bytes.fromhex(h)
                if out:
                    yield from _emit(ctx, out, "hex")
            except ValueError:
                return


@solver("hex-in-text", lambda fp: .45 if fp["charset"] == "ascii-text" and re.search(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{16,}", fp.get("_text", "")) else 0.0)
def solve_hex_in_text(data, ctx):
    """Decode long hex-looking runs embedded in surrounding prose (e.g.
    'The value is 6163...7d here.'). Only yields when the decoded bytes are
    printable text, and only for runs whose decoded form looks flag-like or
    English-ish."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    seen = set()
    for m in re.finditer(r"(?<![0-9a-fA-F])([0-9a-fA-F]{16,})(?![0-9a-fA-F])", text):
        tok = m.group(1)
        if len(tok) % 2:
            continue
        try:
            out = bytes.fromhex(tok)
        except ValueError:
            continue
        if out in seen:
            continue
        seen.add(out)
        pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / len(out)
        if pr >= 0.9:
            yield out, "hex-in-text", {"start": m.start()}, assess(out)[0]


_HEX_ROT13_RE = re.compile(r"[0-9nopqrs]+")
_ROT13_HEX_TBL = str.maketrans("nopqrs", "abcdef")


def _hex_rot13_prior(fp):
    """Fires when the data is a long hex+ROT13 stream: runs of `[0-9nopqrs]`
    (even length >= 16) with at least one ROT13-rotated hex letter n..s, and
    little else in the buffer."""
    text = fp.get("_text", "")
    if len(text) < 16:
        return 0.0
    runs = [r for r in _HEX_ROT13_RE.findall(text)
            if len(r) >= 16 and len(r) % 2 == 0 and re.search(r"[nopqrs]", r)]
    if not runs:
        return 0.0
    engaged = sum(len(r) for r in runs)
    if engaged / len(text) < 0.35:
        return 0.0
    return 0.3


@solver("hex+rot13", _hex_rot13_prior)
def solve_hex_rot13(data, ctx):
    """Recover hex digits whose letters were ROT13-rotated into n..s
    (ROT13 maps a<->n ... f<->s, so n->a ... s->f). Yields the restored hex
    string so the existing hex->base64 layers chain on, and also the directly
    decoded bytes as a shorter alternative path."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    seen = set()
    for m in re.finditer(r"(?<![0-9nopqrs])[0-9nopqrs]{16,}(?![0-9nopqrs])", text):
        tok = m.group(0)
        if len(tok) % 2:
            continue
        restored = tok.translate(_ROT13_HEX_TBL)
        try:
            out = bytes.fromhex(restored)
        except ValueError:
            continue
        if not out or out in seen:
            continue
        seen.add(out)
        pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / len(out)
        params = {"_statistical": True}
        # Restored hex string (chains through the standard hex layer).
        yield restored.encode("ascii"), "hex+rot13", dict(params), .75
        # Direct decode of the restored hex (skips the hex hop).
        if pr >= 0.9:
            yield out, "hex+rot13", dict(params), .8


@solver("base32", lambda fp: _prior(fp, "base32"))
def solve_base32(data, ctx):
    try:
        raw = re.sub(rb"\s+", b"", data).upper()
        out = base64.b32decode(raw + b"=" * ((-len(raw)) % 8))
        if out:
            yield from _emit(ctx, out, "base32")
    except (binascii.Error, ValueError):
        return


@solver("base64", lambda fp: max(_prior(fp, "base64"), _prior(fp, "base64url")))
def solve_base64(data, ctx):
    blobs = [data]
    # Tolerate a leading "<name> = " assignment label before the payload
    # (e.g. "ct = <base64>"), which otherwise breaks the alphabet/length
    # checks. The un-prefixed buffer is always tried first, so existing
    # inputs are unaffected; the stripped form is only a fallback.
    m = re.match(rb"^[A-Za-z_]\w*\s*=\s*", data)
    if m:
        blobs.append(data[m.end():])
    seen = set()
    for blob in blobs:
        raw = re.sub(rb"\s+", b"", blob)
        for url in (False, True):
            try:
                padded = raw + b"=" * ((-len(raw)) % 4)
                out = base64.urlsafe_b64decode(padded) if url else base64.b64decode(padded, validate=True)
                if out and (url == (b"-" in raw or b"_" in raw) or not url) and out not in seen:
                    seen.add(out)
                    yield from _emit(ctx, out, "base64url" if url else "base64")
            except (binascii.Error, ValueError):
                continue
    # Embedded-run extraction: a base64 payload frequently sits inside a larger
    # buffer with non-base64 prose around it (labels, narrations, terse
    # wrappers). When whole-blob decode surfaces nothing, scan for maximal
    # contiguous alphabet runs and try each as a standalone payload.
    if not seen:
        # Scan the raw buffer WITHOUT collapsing whitespace: the trailing/
        # leading prose stays split into short word-runs (which can't reach
        # the minimum length), while a payload that is one contiguous token
        # still forms a single long run.
        b64_run = re.compile(rb"[A-Za-z0-9+/]{16,}")
        b64url_run = re.compile(rb"[A-Za-z0-9_-]{16,}")
        for blob in blobs:
            for url, rx in ((False, b64_run), (True, b64url_run)):
                for tok in rx.finditer(blob):
                    t = tok.group(0)
                    # A genuine payload run carries digits or non-alphabetic
                    # alphabet chars; a pure-letter run is usually prose.
                    # (`t` is bytes, so iterate ints.)
                    if not any(0x30 <= c <= 0x39 or c in b"+/-_" for c in t):
                        continue
                    try:
                        padded = t + b"=" * ((-len(t)) % 4)
                        out = base64.urlsafe_b64decode(padded) if url else base64.b64decode(padded, validate=True)
                    except (binascii.Error, ValueError):
                        continue
                    if not out or len(out) < 8 or out in seen:
                        continue
                    seen.add(out)
                    yield from _emit(ctx, out, "base64url" if url else "base64")
    # A case-swapped alphabet (lower/upper positions exchanged) defeats both the
    # standard and URL-safe decoders; retry the whole blob with every letter's
    # case flipped as a final fallback.
    if not seen:
        t = re.sub(rb"\s+", b"", data)
        if t:
            padded = t.swapcase() + b"=" * ((-len(t)) % 4)
            try:
                out = base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError):
                out = None
            if out and len(out) >= 4 \
                    and sum(32 <= b < 127 for b in out) >= 0.7 * len(out):
                seen.add(out)
                yield from _emit(ctx, out, "base64 (swapcase)")
    # A base64 payload whose direct decode is opaque (non-text) may be a
    # letter-shifted alphabet (e.g. caesar over base64, as in c08's
    # ct = caesar(b64)); try each shift and surface any printable decode so
    # that layer can be undone downstream.
    if not any(all(32 <= b < 127 or b in (9, 10, 13) for b in o) for o in seen):
        for blob in blobs:
            raw = re.sub(rb"\s+", b"", blob)
            for k in range(1, 26):
                shifted = bytes(
                    ((b - 97 - k) % 26 + 97) if 97 <= b <= 122 else
                    ((b - 65 - k) % 26 + 65) if 65 <= b <= 90 else b
                    for b in raw)
                try:
                    padded = shifted + b"=" * ((-len(shifted)) % 4)
                    out = base64.b64decode(padded, validate=True)
                except (binascii.Error, ValueError):
                    continue
                if out and all(32 <= b < 127 or b in (9, 10, 13) for b in out) \
                        and out not in seen:
                    seen.add(out)
                    yield out, "base64", {"caesar_shift": -k}, assess(out)[0]


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@solver("base58", lambda fp: _prior(fp, "base58/base62"))
def solve_base58(data, ctx):
    try:
        s = data.decode("ascii").strip()
        n = 0
        for c in s:
            n = n * 58 + _B58.index(c)
        out = (b"\0" * (len(s) - len(s.lstrip("1"))) +
               (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""))
        if out:
            yield from _emit(ctx, out, "base58")
    except (ValueError, UnicodeError):
        return


@solver("base85", lambda fp: _prior(fp, "base85"))
def solve_base85(data, ctx):
    raw = re.sub(rb"\s+", b"", data)
    for name, fn in (("base85", base64.b85decode), ("ascii85", base64.a85decode)):
        try:
            out = base64.a85decode(raw, adobe=raw.startswith(b"<~")) if name == "ascii85" else fn(raw)
            if out:
                yield from _emit(ctx, out, name)
        except (ValueError, binascii.Error):
            continue


@solver("url", lambda fp: _prior(fp, "url"))
def solve_url(data, ctx):
    try:
        out = urllib.parse.unquote_to_bytes(data.decode("ascii").replace("+", " "))
        if out != data:
            yield from _emit(ctx, out, "url")
    except UnicodeError:
        return


@solver("binary", lambda fp: _prior(fp, "binary"))
def solve_binary(data, ctx):
    try:
        raw = data.decode("ascii", "ignore")
        tokens = [t for t in re.split(r"\s+", raw) if t]
        flat = "".join(tokens)
        bits = re.sub(r"[^01]", "", flat)
        if not bits:
            return
        emitted = []
        # Standard byte stream: 8-bit groups from the start.
        out = bytes(int(bits[i:i + 8], 2)
                    for i in range(0, len(bits) - 7, 8))
        if out:
            yield from _emit(ctx, out, "binary")
            emitted.append(out)
        # Space-separated tokens: left-pad each token to 8 bits so leading-zero
        # stripped bytes recover (e.g. "1001000 1101001" -> "Hi").
        if len(tokens) > 1:
            padded = []
            for t in tokens:
                bbits = re.sub(r"[^01]", "", t)
                if not bbits or len(bbits) > 8:
                    padded = []
                    break
                padded.append("0" * (8 - len(bbits)) + bbits)
            if padded:
                blob = "".join(padded)
                out2 = bytes(int(blob[i:i + 8], 2)
                             for i in range(0, len(blob), 8))
                if out2 and out2 not in emitted:
                    yield from _emit(ctx, out2, "binary (padded)")
    except (ValueError, UnicodeError):
        return


@solver("octal", lambda fp: _prior(fp, "octal"))
def solve_octal(data, ctx):
    try:
        nums = re.findall(rb"\d+", data)
        out = bytes(int(n, 8) for n in nums if int(n, 8) <= 255)
        if out and len(out) == len(nums):
            yield from _emit(ctx, out, "octal")
    except ValueError:
        return


@solver("decimal", lambda fp: _prior(fp, "decimal"))
def solve_decimal(data, ctx):
    try:
        nums = re.findall(rb"\d+", data)
        out = bytes(int(n) for n in nums)
        if out and all(int(n) <= 255 for n in nums):
            yield from _emit(ctx, out, "decimal bytes")
    except (ValueError, OverflowError):
        return


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
    # Common punctuation.
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'",
    "-.-.--": "!", "-..-.": "/", "-.--.": "(", "-.--.-": ")",
    ".-...": "&", "---...": ":", "-.-.-.": ";", "-...-": "=",
    ".-.-.": "+", "-....-": "-", "..--.-": "_", ".-..-.": '"',
    "...-..-": "$", ".--.-.": "@",
}


@solver("morse", lambda fp: _prior(fp, "morse"))
def solve_morse(data, ctx):
    try:
        s = data.decode("ascii", "ignore").strip()
        if not s:
            return
        # '|' is also used as a letter separator in the wild; normalize to space.
        s = s.replace("|", " ")
        # Words are separated by '/' or runs of 2+ spaces; letters by single
        # spaces. Unknown tokens are skipped rather than aborting the decode.
        words = []
        for raw in re.split(r"/|\s{2,}", s):
            raw = raw.strip()
            if not raw:
                continue
            letters = [_MORSE[t] for t in raw.split() if t in _MORSE]
            if letters:
                words.append("".join(letters))
        out = " ".join(words)
        if out:
            yield from _emit(ctx, out, "morse")
    except UnicodeError:
        return


@solver("quoted-printable", lambda fp: _prior(fp, "quoted-printable"))
def solve_qp(data, ctx):
    if b"=" not in data:
        return
    try:
        out = binascii.a2b_qp(data)
        if out != data:
            yield from _emit(ctx, out, "quoted-printable")
    except binascii.Error:
        return


@solver("a1z26", lambda fp: _prior(fp, "a1z26/polybius"))
def solve_a1z26(data, ctx):
    nums = re.findall(rb"\d+", data)
    try:
        if nums and all(1 <= int(n) <= 26 for n in nums):
            yield from _emit(ctx, "".join(chr(96 + int(n)) for n in nums), "A1Z26")
    except ValueError:
        return


@solver("bacon", lambda fp: _prior(fp, "bacon"))
def solve_bacon(data, ctx):
    bits = re.sub(rb"[^aAbB]", b"", data).upper()
    if len(bits) < 5:
        return
    table = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    try:
        out = "".join(table[int(bits[i:i + 5].replace(b"A", b"0").replace(b"B", b"1"), 2)]
                      for i in range(0, len(bits) - 4, 5))
        yield from _emit(ctx, out, "Bacon")
    except (ValueError, IndexError):
        return


@solver("polybius", lambda fp: _prior(fp, "polybius", "a1z26/polybius"))
def solve_polybius(data, ctx):
    digits = re.sub(rb"\s+", b"", data)
    if len(digits) < 4 or len(digits) % 2 or not re.fullmatch(rb"[1-5]+", digits):
        return
    try:
        chars = []
        for i in range(0, len(digits), 2):
            r, c = int(digits[i:i + 1]), int(digits[i + 1:i + 2])
            chars.append("ABCDEFGHIKLMNOPQRSTUVWXYZ"[(r - 1) * 5 + c - 1])
        yield from _emit(ctx, "".join(chars), "Polybius")
    except (ValueError, IndexError):
        return


@solver("PEM", lambda fp: _prior(fp, "pem"))
def solve_pem(data, ctx):
    try:
        body = b"".join(line.strip() for line in data.splitlines()
                        if line and not line.startswith(b"-----"))
        out = base64.b64decode(body, validate=True)
        if out:
            yield from _emit(ctx, out, "PEM/base64")
    except binascii.Error:
        return


@solver("zlib/gzip", lambda fp: max(
    _prior(fp, "gzip"), _prior(fp, "zlib"),
    (.35 if fp["charset"] == "binary" and 4 <= fp["length"] <= 10_000_000 else 0.0)))
def solve_compression(data, ctx):
    try:
        if data.startswith(b"\x1f\x8b"):
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = obj.decompress(data, 10_000_001)
            if len(out) <= 10_000_000 and obj.eof:
                yield from _emit(ctx, out, "gzip")
        elif data.startswith(b"BZh"):
            # bzip2 (Phase 6): magic 'BZh' + block size digit.
            out = bz2.decompress(data)
            if len(out) <= 10_000_000:
                yield from _emit(ctx, out, "bzip2")
        elif len(data) >= 2 and data[0] == 0x78:
            obj = zlib.decompressobj()
            out = obj.decompress(data, 10_000_001)
            if len(out) <= 10_000_000 and obj.eof:
                yield from _emit(ctx, out, "zlib")
    except (zlib.error, OSError, ValueError):
        return


@solver("utf16-text", lambda fp: .30 if fp["charset"] in ("binary", "mixed") and fp["length"] >= 4 else 0)
def solve_utf16_text(data, ctx):
    """Decode UTF-16/UTF-32 text (LE/BE), BOM-autodetected (Phase 6)."""
    pairs = []
    if data.startswith(b"\xff\xfe\x00\x00") and len(data) % 4 == 0:
        pairs.append(("utf-32-le", data[4:]))
    elif data.startswith(b"\x00\x00\xfe\xff") and len(data) % 4 == 0:
        pairs.append(("utf-32-be", data[4:]))
    elif data.startswith(b"\xff\xfe") and len(data) % 2 == 0:
        pairs.append(("utf-16-le", data[2:]))
    elif data.startswith(b"\xfe\xff") and len(data) % 2 == 0:
        pairs.append(("utf-16-be", data[2:]))
    else:
        if len(data) % 4 == 0:
            pairs.append(("utf-32-le", data))
            pairs.append(("utf-32-be", data))
        if len(data) % 2 == 0:
            pairs.append(("utf-16-le", data))
            pairs.append(("utf-16-be", data))
    seen = set()
    for name, raw in pairs:
        if name in seen:
            continue
        seen.add(name)
        try:
            txt = raw.decode(name, "strict")
        except (UnicodeDecodeError, ValueError):
            continue
        if not txt.strip():
            continue
        printable = sum(c.isprintable() or c in "\r\n\t " for c in txt) / max(1, len(txt))
        if printable < 0.8:
            continue
        sc = _rank_score(txt)
        pf = flag_plausibility(txt)
        fo = _hint_flag_only(txt)
        if fo:
            yield fo, name, {}, .99
        elif pf > 0 or sc >= .55:
            conf = .97 if pf > 0 else max(.6, min(.95, sc))
            yield txt, name, {}, conf
        else:
            yield txt, name, {}, max(.5, sc)


@solver("reverse", lambda fp: .35 if fp["charset"] == "ascii-text" and fp["length"] > 3 else 0)
def solve_reverse(data, ctx):
    try:
        out = data.decode("utf-8")[::-1]
        yield from _emit(ctx, out, "reverse text")
    except UnicodeDecodeError:
        return


def _letter_shift(text, fn):
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((fn(ord(c) - 97) % 26) + 97))
        elif "A" <= c <= "Z":
            out.append(chr((fn(ord(c) - 65) % 26) + 65))
        else:
            out.append(c)
    return "".join(out)


def _rank_score(out):
    """assess() for ordinary text; leetspeak-aware flag plausibility if flag-shaped."""
    a = assess(out)[0]
    f = flag_plausibility(out if isinstance(out, str) else out.decode("utf-8", "replace"))
    return max(a, f) if f > 0 else a


_FLAG_ONLY_RE = re.compile(r"[A-Za-z0-9_]{1,40}\{[^{}\s]{0,300}\}")
_KNOWN_PFX = ("flag{", "ctf{", "picoctf{", "htb{", "ictf{", "dice{",
              "academy{", "thm{", "geek{", "cuhk24ctf{", "mini{")


def _hint_flag_only(s):
    """Return a known-prefix flag substring (e.g. 'academy{...}') if present."""
    m = _FLAG_ONLY_RE.search(s or "")
    if m and m.group(0).lower().startswith(_KNOWN_PFX):
        return m.group(0)
    return None


def _top_texts(text, variants, count=3):
    ranked = sorted(((_rank_score(out), out, method, params) for out, method, params in variants),
                    reverse=True, key=lambda x: x[0])
    return ranked[:count]


@solver("caesar", lambda fp: _text_prior(fp))
def solve_caesar(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    if re.fullmatch(r"[0-9a-fA-F\s]+", text) and len(re.sub(r"\s", "", text)) >= 16:
        # Pure hex/digest-looking blobs are not Caesar text; trying shifts here
        # spawns combinatorial junk children (and starves real solvers).
        return
    # Source hint: `shift=N` (challenge.py) gives the exact key — decrypt it
    # directly and skip the exhaustive all-shifts loop.
    _sm = re.search(r"(?m)^\s*shift\s*=\s*(\d+)\s*$", text)
    if _sm:
        k = int(_sm.group(1))
        if 1 <= k < 26:
            out = _letter_shift(text, lambda x, k=k: x - k)
            fo = _hint_flag_only(out)
            if fo:
                yield fo, "caesar(hint)", {"shift": k, "_statistical": True}, .99
                return
            sc = _rank_score(out)
            pf = flag_plausibility(out)
            if pf > 0 or sc >= .55:
                claimed = .97 if pf > 0 else max(.6, min(.95, sc))
                yield out, "caesar(hint)", {"shift": k, "_statistical": True}, claimed
                return
    variants = [(_letter_shift(text, lambda x, k=k: x - k), "caesar", {"shift": k})
                for k in range(1, 26)]
    if len(text) <= 200 and (any(not c.isalpha() for c in text) or any(c.islower() for c in text)):
        ranked = sorted(((_rank_score(out), out, method, params) for out, method, params in variants),
                        reverse=True, key=lambda x: x[0])
        for i, (score, out, method, params) in enumerate(ranked):
            if i == 0:
                params["_relative_candidate"] = True
            yield out, method, params, score
    elif ctx.depth >= 1:
        # Intermediate classical layer: the true shift can rank below the
        # final-plaintext top-3, so keep all 25 shifts reachable for the
        # next layer in a stack (e.g. vigenere -> caesar -> ...).
        for score, out, method, params in sorted(
                ((_rank_score(out), out, method, params) for out, method, params in variants),
                reverse=True, key=lambda x: x[0]):
            yield out, method, params, score
    else:
        for score, out, method, params in _top_texts(text, variants, 3):
            yield out, method, params, score


@solver("ROT13", lambda fp: _text_prior(fp))
def solve_rot13(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    rot = _letter_shift(text, lambda x: x - 13)
    # ROT13 may reveal a recognized flag wrapper (e.g. "academy{…}") possibly
    # preceded by stray padding. Surface the canonical flag shell itself so it
    # ranks as a full-buffer recovery instead of a partial-cover substring.
    _w = re.search(r"(?:academy|flag|ctf|picoctf|htb|thm|dice)\{.*?\}", rot, re.I)
    if _w:
        _shell = _w.group(0)
        if leet_body_dict_fraction(_shell) > leet_body_dict_fraction(text) + 0.03:
            yield _shell, "cracked ROT13", {"_statistical": True}, 0.99
            return
    yield from _emit(ctx, rot, "rot13")


@solver("ROT47", lambda fp: _text_prior(fp))
def solve_rot47(data, ctx):
    try:
        text = data.decode("utf-8")
        out = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)
        yield from _emit(ctx, out, "rot47")
    except UnicodeDecodeError:
        return


@solver("atbash", lambda fp: _text_prior(fp))
def solve_atbash(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    out = _letter_shift(text, lambda x: 25 - x)
    # When the input is a flag-shaped blob whose body is NOT already readable
    # English (i.e. it is ciphertext rather than a real flag), atbash is a fully
    # specified deterministic transform and the hint in read.md ("Add atbash
    # cypher") tells us it is the intended step. Surface the atbash translation
    # as a first-class recovery. Genuine readable flags are left untouched.
    if "{" in text and not clear_english(text):
        _ms = re.search(r"(?:academy|flag|ctf|picoctf|htb|thm|dice)\{.*?\}", out, re.I)
        if _ms and _ms.group(0) != text and re.search(r"\w{1,40}\{.*?\}", out):
            yield _ms.group(0), "cracked atbash", {"_statistical": True}, 0.99
            return
    yield from _emit(ctx, out, "atbash")


# Mixed alphanumeric Caesar: shift over a base-36 alphabet
# "0123456789abcdefghijklmnopqrstuvwxyz". Catches challenges whose ciphertext
# interleaves digits into words (e.g. CSAW "Caesar Salad Edition"):
# y4tz{...} -> flag{...} is a +17 rotate on that alphabet.
_ALNUM36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _alnum_caesar_prior(fp):
    if fp.get("charset") != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    n = len(t)
    if n < 8 or n > 2000:
        return 0.0
    # Need a digit adjacent to a letter (alphanumeric cipher words), so a
    # plain number or pure-hex blob is not tempted.
    if not re.search(r"(?i)[a-z][0-9]|[0-9][a-z]", t):
        return 0.0
    frac = sum(1 for c in t.lower() if c in _ALNUM36) / max(1, n)
    if frac < 0.7:
        return 0.0
    return 0.4


@solver("base36-caesar", _alnum_caesar_prior)
def solve_base36_caesar(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    if re.fullmatch(r"[0-9a-fA-F\s]+", text) and len(re.sub(r"\s", "", text)) >= 16:
        # Pure hex/digest-looking blobs: not an alphanumeric Caesar.
        return
    variants = []
    for k in range(1, 36):
        out = []
        for ch in text:
            low = ch.lower()
            idx = _ALNUM36.find(low)
            if idx != -1:
                rep = _ALNUM36[(idx + k) % 36]
                out.append(rep.upper() if ch.isupper() else rep)
            else:
                out.append(ch)
        variants.append(("".join(out), "base36-caesar", {"shift": k}))
    def _has_known_flag(o):
        lo = o.lower()
        return any(p in lo for p in ("flag{", "ctf{", "picoctf{", "academy{",
                                     "htb{", "ictf{", "dice{", "thm{"))
    entries = []
    for o, m, p in variants:
        sc = _rank_score(o)
        fb = _has_known_flag(o)
        # A decode that yields a known-prefix flag inside plausible English is
        # an authoritative recovery; give it enough confidence to outrank an
        # as-is "flag-shaped" row (which sits at the ~0.96 floor).
        claim = max(sc, 0.97) if fb and sc >= 0.5 else sc
        entries.append((1.0 if fb else 0.0, sc, claim, o, m, p))
    ranked = sorted(entries, key=lambda x: (x[0], x[1]), reverse=True)
    for i, (_fb, sc, claim, out, method, params) in enumerate(ranked[:3]):
        if i == 0:
            params["_relative_candidate"] = True
        yield out, method, params, claim


# picoCTF-style "b16 + shift" Vigenere over the 16-letter alphabet
# abcdefghijklmnop: each plaintext byte is base-16 encoded as two symbols
# (high/low nibble -> a..p), then each symbol is shifted by a key symbol with
# a Vigenere-reduced mod 16 (New_Caesar / New_Vignere family). The b16
# structure is a strong oracle: every first-of-pair symbol must decode to a
# printable-ASCII high nibble in {2..7}, which collapses the key space so we
# can backtrack a key of any feasible period < 15.
_B16_ALPHA = "abcdefghijklmnop"
_B16_HIGH = frozenset(range(2, 8))  # high nibbles of 0x20..0x7E


def _b16_shift_prior(fp):
    if fp.get("charset") != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    nospace = re.sub(r"\s", "", t)
    if not 8 <= len(nospace) <= 600:
        return 0.0
    letters = [c for c in t.lower() if c in _B16_ALPHA]
    if not 8 <= len(letters) <= 600 or len(letters) % 2:
        return 0.0
    if len(letters) / max(1, len(nospace)) < 0.85:
        return 0.0
    # Very specific fingerprint (>=85% a..p letters, even length): a strong
    # prior that still sits below the RSA/known-plaintext solvers but above
    # the generic classical-cipher ones, so it isn't starved by budget.
    return 0.72


@solver("b16-shift-vigenere", _b16_shift_prior)
def solve_b16_shift_vigenere(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    letters = [ord(c) - 97 for c in text.lower() if c in _B16_ALPHA]
    L = len(letters)
    if L < 8 or L % 2 or L > 3000:
        return

    def decode_score(keyval):
        out_chars = []
        for i in range(0, L, 2):
            vh = (letters[i] - keyval[i % p]) % 16
            vl = (letters[i + 1] - keyval[(i + 1) % p]) % 16
            b = vh * 16 + vl
            if not 32 <= b <= 126:
                return -1.0, ""
            out_chars.append(chr(b))
        out = "".join(out_chars)
        return _rank_score(out), out

    best = None
    max_p = min(14, L // 2)
    for p in range(1, max_p + 1):
        cand, free = [], []
        for r in range(p):
            s = set(range(16))
            has_even = False
            i = r
            while i < L:
                if i % 2 == 0:
                    has_even = True
                    s &= {(letters[i] - v) % 16 for v in _B16_HIGH}
                i += p
            if not s:
                break
            if has_even:
                cand.append((r, sorted(s)))
            else:
                free.append(r)
        if len(cand) + len(free) < p:
            continue
        constrained_product = 1
        for _r, s in cand:
            constrained_product *= len(s)
        if constrained_product > 50000:
            continue  # even constrained half is too large to explore
        # Full enumeration when feasible (covers even periods up to ~p=6);
        # otherwise use a greedy per-free-residue optimization for the odd
        # (low-nibble-only) key symbols, which don't affect printability.
        full_combos = constrained_product * (16 ** len(free))
        domains = [s for _r, s in cand] + [list(range(16)) for _ in free]
        residues = [r for r, _ in cand] + free
        if full_combos <= 1_200_000:
            keys = itertools.product(*domains)
        else:
            # Greedy: enumerate constrained residues, optimize free residues one
            # at a time (each only touches disjoint odd positions).
            def _gen():
                for cvals in itertools.product(*[s for _r, s in cand]):
                    keyval = dict(zip([r for r, _ in cand], cvals))
                    for r in free:
                        keyval[r] = 0
                    for _pass in range(3):
                        for r in free:
                            bestv, bestsc = keyval[r], -1.0
                            for v in range(16):
                                keyval[r] = v
                                sc, _t = decode_score(keyval)
                                if sc > bestsc:
                                    bestsc, bestv = sc, v
                            keyval[r] = bestv
                    yield tuple(keyval[r] for r in [rr for rr, _ in cand] + free)
            keys = _gen()
        for values in keys:
            keyval = dict(zip(residues, values))
            sc, out = decode_score(keyval)
            if sc <= 0:
                continue
            fb = 1.0 if _hint_flag_only(out) else 0.0
            # `_rank_score` can overvalue `...{...}`-shaped printable text, so
            # rank by (known-flag-prefix, flag-body dictionary coverage, score):
            # a correct decode reads as words in the flag body, a wrong one
            # rarely does.
            leet = leet_body_dict_fraction(out)
            if best is None or (fb, leet, sc) > (best[1], best[2], best[0]):
                best = (sc, fb, leet, out, p,
                        tuple(_B16_ALPHA[keyval[r]] for r in range(p)))
    if best is None:
        return
    sc, fb, leet, out, p, keychars = best
    claim = max(sc, 0.95) if fb else max(sc, 0.75)
    yield out, "b16-shift-vigenere", {"period": p, "key": "".join(keychars)}, claim


_FLAG_BODY_SHELL_RE = re.compile(r"^([A-Za-z]+)\{([^{}\s]{1,300})\}$")
_VIG_BUILTIN_KEYS = (
    "key secret password flag ctf crypto cipher lemon pass admin hello world test "
    "cat dog abc abcd picoctf secure vigenere caesar encrypt decrypt python hacker "
    "cyber security academy pico thm htb root toor letmein qwerty").split()


def _flag_body_prior(fp):
    """Narrow: fire only when the whole input is a flag-shaped string
    (letter-prefix `{` … `}`). Never fires on ordinary text/encodings."""
    text = fp.get("_text", "")
    if not _FLAG_BODY_SHELL_RE.search(text.strip()):
        return 0.0
    return 0.3


def _flag_body_vig_decrypt(body, word):
    ks = [ord(c) - 97 for c in word.lower()]
    j = 0
    out = []
    for ch in body:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - ks[j % len(ks)]) % 26 + 97))
            j += 1
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - ks[j % len(ks)]) % 26 + 65))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


@solver("flag-body-decode", _flag_body_prior)
def solve_flag_body_decode(data, ctx):
    """If the input is already a flag whose *body* is NOT plausible English
    (e.g. classical ciphertext inside a `{…}` shell), try simple decodes of
    the body — all Caesar shifts (1..25, ROT13 is shift 13), atbash, and a
    short Vigenere dictionary attempt — and surface any result clearly more
    plausible than the original body, preserving the prefix{}/} shell. A
    genuine, already-plausible plaintext flag is left untouched."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    m = _FLAG_BODY_SHELL_RE.match(text.strip())
    if not m:
        return
    prefix, body = m.group(1), m.group(2)
    full = f"{prefix}{{{body}}}"
    orig_plaus = flag_plausibility(full)
    if orig_plaus >= 0.5 or english_confidence(body) >= 0.5:
        return
    best = []  # (flag_plausibility, english_conf, decoded_body, method)
    for k in range(1, 26):          # Caesar shifts; ROT13 == shift 13
        db = _letter_shift(body, lambda x, k=k: x + k)
        if db != body:
            cf = f"{prefix}{{{db}}}"
            best.append((flag_plausibility(cf), english_confidence(db), db,
                         f"flag-body caesar({k})"))
    db = _letter_shift(body, lambda x: 25 - x)   # atbash
    if db != body:
        cf = f"{prefix}{{{db}}}"
        best.append((flag_plausibility(cf), english_confidence(db), db,
                     "flag-body atbash"))
    for word in _VIG_BUILTIN_KEYS + [w for w in ctx.wordlist[:200]
                                      if isinstance(w, str) and w.isascii() and w.isalpha()]:
        db = _flag_body_vig_decrypt(body, word)
        if db != body:
            cf = f"{prefix}{{{db}}}"
            best.append((flag_plausibility(cf), english_confidence(db), db,
                         f"flag-body vigenere({word.upper()})"))
    best.sort(key=lambda t: (t[0], t[1]), reverse=True)
    emitted = set()
    for plaus, ec, db, method in best:
        # Only surface candidates clearly more plausible than the original body.
        if plaus - orig_plaus >= 0.15 or ec >= 0.4:
            if db in emitted:
                continue
            emitted.add(db)
            claim = min(0.97, 0.62 + 0.35 * min(1.0, plaus))
            yield f"{prefix}{{{db}}}", method, {}, claim


@solver("affine", lambda fp: _text_prior(fp))
def solve_affine(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    # Rank ALL 312 keys by the best of plain-English and flag-plausibility
    # evidence (a short flag-shaped plaintext barely moves the quadgram
    # score, so English-only ranking prunes the true key; conversely a
    # flag-shaped junk row must not beat a fuller-evidence row). Yield the
    # top 10; the core ranking then separates ties by leet-body evidence.
    scored = []
    seen = set()
    _flagish_local = re.compile(r"[A-Za-z0-9_]{2,30}\{[^{}\s]{1,300}\}")
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        inv = pow(a, -1, 26)
        for b in range(26):
            out = _letter_shift(text, lambda x, inv=inv, b=b: inv * (x - b))
            if out in seen:
                continue
            seen.add(out)
            m = _flagish_local.search(out)
            if m and (m.end() - m.start()) >= 0.9 * max(1, len(out)):
                # Flag-shaped candidate: evidence = real leet-word coverage of
                # the body (flag_plausibility is not word-aware and can rank
                # junk above a dictionary-body flag).
                sc = 0.9 + leet_body_dict_fraction(out)
            else:
                sc = max(assess(out)[0], flag_plausibility(out))
            scored.append((sc, out, a, b))
    scored.sort(key=lambda t: -t[0])
    # At intermediate depth the true affine key can rank below the final-
    # plaintext top-10; keep the whole (tiny) key space reachable so a
    # stacked classical chain (e.g. vigenere -> affine -> caesar) can
    # compose. At the surface, top-10 pruning still applies.
    _cut = len(scored) if ctx.depth >= 1 else 10
    for i, (sc, out, a, b) in enumerate(scored[:_cut]):
        yield out, "affine", {"a": a, "b": b}, sc


@solver("vigenere-family", lambda fp: _text_prior(fp))
def solve_vigenere(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    # Source hint: `key_bytes=0x..` (challenge.py) gives the exact key. The
    # printed output usually carries a label prefix ("ct = ") that is NOT part
    # of the ciphertext, so scan leading offsets to align the key.
    _kbm = re.search(r"(?m)^\s*key_bytes\s*=\s*0x([0-9a-fA-F]+)\s*$", text)
    if _kbm:
        try:
            _word = bytes.fromhex(_kbm.group(1)).decode("utf-8")
        except Exception:
            _word = None
        if _word and _word.isalpha() and 2 <= len(_word) <= 24:
            ks = [ord(c) - 97 for c in _word.lower()]
            best = None
            for s in range(0, min(8, len(text))):
                j, out = 0, []
                for c in text:
                    if c.lower() in string.ascii_lowercase:
                        if j < s:
                            out.append(c); j += 1; continue
                        k = ks[(j - s) % len(ks)]
                        x = ord(c.lower()) - 97
                        out.append(chr((x - k) % 26 + (65 if c.isupper() else 97)))
                        j += 1
                    else:
                        out.append(c)
                plain = "".join(out)
                sc, pf = _rank_score(plain), flag_plausibility(plain)
                if best is None or max(sc, pf) > best[0]:
                    best = (max(sc, pf), plain)
            if best and best[1]:
                sc, plain = best
                fo = _hint_flag_only(plain)
                if fo:
                    yield fo, "vigenere(hint)", {"key": _word.upper(), "_statistical": True}, .99
                    return
                if flag_plausibility(plain) > 0 or sc >= .55:
                    claimed = .97 if flag_plausibility(plain) > 0 else max(.6, min(.95, sc))
                    yield plain, "vigenere(hint)", {"key": _word.upper(), "_statistical": True}, claimed
                    return
    # Phase 4: user-supplied key (--key). Decrypt directly; a leading label
    # prefix ("ct = ") may precede the real ciphertext, so scan small offsets.
    if getattr(ctx, "key", ""):
        w = ctx.key.strip().lower()
        if 2 <= len(w) <= 32 and w.isalpha():
            ks = [ord(c) - 97 for c in w]
            best = None
            for s in range(0, min(8, len(text))):
                j, out = 0, []
                for c in text:
                    if c.lower() in string.ascii_lowercase:
                        if j < s:
                            out.append(c); j += 1; continue
                        k = ks[(j - s) % len(ks)]
                        x = ord(c.lower()) - 97
                        out.append(chr((x - k) % 26 + (65 if c.isupper() else 97)))
                        j += 1
                    else:
                        out.append(c)
                plain = "".join(out)
                sc, pf = _rank_score(plain), flag_plausibility(plain)
                if best is None or max(sc, pf) > best[0]:
                    best = (max(sc, pf), plain)
            if best and best[1]:
                sc, plain = best
                fo = _hint_flag_only(plain)
                if fo:
                    yield fo, "vigenere(key)", {"key": w.upper()}, .99
                    return
                if pf > 0 or sc >= .55:
                    claimed = .97 if pf > 0 else max(.6, min(.95, sc))
                    yield plain, "vigenere(key)", {"key": w.upper()}, claimed
                    return
                yield plain, "vigenere(key)", {"key": w.upper()}, max(.5, sc)
                return
    letters = [c.lower() for c in text if c.isalpha() and c.lower() in string.ascii_lowercase]
    if len(letters) < 8:
        return
    vals = [ord(c) - 97 for c in letters]
    maxlen = min(32, len(vals) // 3)
    # Rank periods by the average within-column IC; still inspect a broad set
    # to avoid discarding true periods on short or atypical English samples.
    periods = []
    for size in range(1, maxlen + 1):
        col_ics = []
        for col in range(size):
            seq = vals[col::size]
            n = len(seq)
            freq = collections.Counter(seq)
            col_ics.append(sum(v * (v - 1) for v in freq.values()) / max(1, n * (n - 1)))
        avg = sum(col_ics) / len(col_ics)
        periods.append((abs(avg - .066), size))
    lens = [k for _, k in sorted(periods)[:min(24, len(periods))] if k * 10 <= len(vals)] or [1]
    candidates = []
    for mode in ("vigenere", "beaufort", "variant-beaufort"):
        for keylen in lens:
            key = []
            for col in range(keylen):
                seq = vals[col::keylen]
                freq = collections.Counter(seq)
                best = (float("inf"), 0)
                for k in range(26):
                    counts = [0] * 26
                    for c, amount in freq.items():
                        p = ((c - k) % 26 if mode == "vigenere"
                             else (k - c) % 26 if mode == "beaufort"
                             else (c + k) % 26)
                        counts[p] += amount
                    chi = sum((counts[i] - len(seq) * _EN_FREQ[i]) ** 2 /
                              max(.0001, len(seq) * _EN_FREQ[i]) for i in range(26))
                    if chi < best[0]:
                        best = chi, k
                key.append(best[1])
            # Collapse repeated periods and prefer the shortest equivalent key.
            actual = key
            for size in range(1, len(key) + 1):
                if len(key) % size == 0 and key == key[:size] * (len(key) // size):
                    actual = key[:size]
                    break
            j = 0
            out = []
            for c in text:
                if c.lower() in string.ascii_lowercase:
                    x, k = ord(c.lower()) - 97, actual[j % len(actual)]
                    p = (x - k) % 26 if mode == "vigenere" else (k - x) % 26 if mode == "beaufort" else (x + k) % 26
                    out.append(chr(p + (65 if c.isupper() else 97)))
                    j += 1
                else:
                    out.append(c)
            plain = "".join(out)
            score = _rank_score(plain) - .0015 * len(actual)
            candidates.append((score, plain, mode, "".join(chr(65 + k) for k in actual)))
    # A supplied wordlist can supply the key directly (short ciphertexts cannot
    # be attacked statistically, but dictionary keys can be tried exhaustively).
    _builtin = [w.encode() for w in (
        "key secret password flag ctf crypto cipher lemon pass admin hello world test "
        "cat dog abc abcd picoctf secure vigenere caesar encrypt decrypt python hacker "
        "cyber security academy pico thm htb root toor letmein qwerty").split()]
    if _kbm and _word and _word.isalpha() and 2 <= len(_word) <= 24:
        _builtin.insert(0, _word.lower().encode())
    for raw in _builtin + list(ctx.wordlist[:50_000]):
        word = raw.decode("ascii", "ignore").strip().lower()
        if not (2 <= len(word) <= 24) or not word.isalpha():
            continue
        if ctx.expired():
            break
        ks = [ord(c) - 97 for c in word]
        for mode in ("vigenere", "beaufort"):
            j, out = 0, []
            for c in text:
                if c.lower() in string.ascii_lowercase:
                    x, k = ord(c.lower()) - 97, ks[j % len(ks)]
                    p = (x - k) % 26 if mode == "vigenere" else (k - x) % 26
                    out.append(chr(p + (65 if c.isupper() else 97)))
                    j += 1
                else:
                    out.append(c)
            plain = "".join(out)
            candidates.append((_rank_score(plain) - .0005, plain, mode + "-wordlist", word.upper()))
    for score, plain, mode, key in sorted(candidates, reverse=True)[:48]:
        yield plain, mode, {"key": key}, score


@solver("autokey", lambda fp: _text_prior(fp) if fp["length"] >= 16 else 0)
def solve_autokey(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    vals = [ord(c.lower()) - 97 for c in text if c.lower() in string.ascii_lowercase]
    if len(vals) < 12:
        return
    primers = []
    if ctx.known_plaintext:
        crib = [ord(c.lower()) - 97 for c in ctx.known_plaintext if c.lower() in string.ascii_lowercase]
        if crib:
            for size in range(1, min(32, len(crib), len(vals)) + 1):
                key = [(vals[i] - crib[i]) % 26 for i in range(min(size, len(crib)))]
                if len(key) == size:
                    primers.append(key)
    primers.extend([[ord(c) - 97 for c in word] for word in
                    ("KEY", "LEMON", "SECRET", "ORANGE", "CRYPTO")
                    if len(word) <= len(vals)])
    seen = set()
    for key in primers:
        if not key or tuple(key) in seen:
            continue
        seen.add(tuple(key))
        plain_vals = []
        for i, c in enumerate(vals):
            k = key[i] if i < len(key) else plain_vals[i - len(key)]
            plain_vals.append((c - k) % 26)
        it = iter(plain_vals)
        out = "".join(chr(next(it) + (65 if c.isupper() else 97))
                      if c.lower() in string.ascii_lowercase else c for c in text)
        if ctx.known_plaintext and ctx.known_plaintext.lower() not in out.lower():
            continue
        yield from _emit(ctx, out, "autokey", {"primer": "".join(chr(97 + k) for k in key)})


_EN_FREQ = [.08167, .01492, .02782, .04253, .12702, .02228, .02015, .06094,
            .06966, .00153, .00772, .04025, .02406, .06749, .07507, .01929,
            .00095, .05987, .06327, .09056, .02758, .00978, .02360, .00150,
            .01974, .00074]


def _rail_decode(text, rails):
    if rails <= 1:
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rail_ids = [pattern[i % len(pattern)] for i in range(len(text))]
    counts = [rail_ids.count(r) for r in range(rails)]
    pos, chunks = 0, []
    for count in counts:
        chunks.append(list(text[pos:pos + count]))
        pos += count
    idx = [0] * rails
    out = []
    for rail in rail_ids:
        out.append(chunks[rail][idx[rail]])
        idx[rail] += 1
    return "".join(out)


@solver("rail-fence", lambda fp: _text_prior(fp))
def solve_rail(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    variants = [(_rail_decode(text, rails), "rail fence", {"rails": rails})
                for rails in range(2, min(21, len(text)))]
    # For flag-shaped inputs, order by leet-body dictionary evidence first
    # (flag_plausibility saturates at 1.0 for junk), then by rank score. Keep
    # more candidates than usual so the genuine rail survives to core ranking.
    if "{" in text:
        variants.sort(key=lambda v: (leet_body_dict_fraction(v[0]), _rank_score(v[0])),
                      reverse=True)
        chosen = variants[:8]
    else:
        chosen = [(out, method, params) for _, out, method, params in _top_texts(text, variants, 3)]
    ranked = [(_rank_score(out), out, method, params) for out, method, params in chosen]
    distinctive = len(ranked) > 1 and ranked[0][0] - ranked[1][0] >= .15
    for i, (score, out, method, params) in enumerate(ranked):
        if i == 0 and distinctive:
            params["_relative_candidate"] = True
        if i == 0:
            # A transposition decode that reads as a real English sentence
            # (even with leet-digit words like "WH3R3") is a genuine recovery.
            # Short-text statistical scoring underrates such phrases, so promote
            # them above junk/XOR noise (which lacks common-word structure).
            _toks = re.findall(r"[A-Za-z]+", out)
            _common_hits = sum(1 for t in _toks if t.lower() in _COMMON)
            if (len(out) >= 16
                    and sum(ch.isalpha() for ch in out) >= 12
                    and len(_toks) >= 4
                    and _common_hits >= 2):
                params["_statistical"] = True
                yield out, method, params, round(min(0.95, 0.78 + 0.06 * _common_hits), 3)
                continue
        yield out, method, params, score


@solver("scytale", lambda fp: _text_prior(fp))
def solve_scytale(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    variants = []
    for rows in range(2, min(20, len(text))):
        cols = math.ceil(len(text) / rows)
        out = "".join(text[r * cols + c] for c in range(cols) for r in range(rows)
                      if r * cols + c < len(text))
        variants.append((out, "scytale", {"rows": rows}))
    for score, out, method, params in _top_texts(text, variants, 2):
        yield out, method, params, score


def _columnar_decrypt(text, order):
    n, cols = len(text), len(order)
    rows, extra = divmod(n, cols)
    heights = [rows + (i < extra) for i in range(cols)]
    columns = [""] * cols
    pos = 0
    for col in order:
        h = heights[col]
        columns[col] = text[pos:pos + h]
        pos += h
    return "".join(columns[c][r] for r in range(rows + 1) for c in range(cols)
                   if r < len(columns[c]))


def _column_worker(args):
    text, seed, rounds = args
    rng = random.Random(seed)
    best = ("", -999.0)
    for cols in range(2, min(13, len(text) // 8 + 1)):
        order = list(range(cols))
        rng.shuffle(order)
        cur = _columnar_decrypt(text, order)
        score = quadgram_score(cur)
        temp = .45
        for i in range(rounds):
            a, b = rng.sample(range(cols), 2)
            order[a], order[b] = order[b], order[a]
            trial = _columnar_decrypt(text, order)
            q = quadgram_score(trial)
            if q > score or rng.random() < math.exp(min(0.0, (q - score) / temp)):
                cur, score = trial, q
            else:
                order[a], order[b] = order[b], order[a]
            temp = .45 * (1 - i / max(1, rounds)) + .015
        if score > best[1]:
            best = cur, score
    return best


def _parallel_map(worker, args, ctx):
    if ctx.expired():
        ctx.failures.append("Parallel solver skipped: time budget already expired.")
        return []
    import os as _os
    if _os.environ.get("AUTOCRYPT_WORKER") == "1":
        # inside a G1 worker process: never spawn nested pools
        try:
            return [worker(arg) for arg in args]
        except Exception as exc:
            ctx.failures.append(f"Parallel solver failed: {type(exc).__name__}: {exc}")
            return []
    if len(args) <= 1:
        try:
            return [worker(arg) for arg in args]
        except Exception as exc:
            ctx.failures.append(f"Parallel solver failed: {type(exc).__name__}: {exc}")
            return []
    # For very small workloads the process-pool overhead (especially the
    # Windows `spawn` start method, ~0.5-1s per process) far exceeds the
    # work itself. Keep it serial so small buffers aren't slowed by pool
    # spin-up; the pool is only worth it when each job is meaty.
    if ctx.pool is None and sum(len(a) if isinstance(a, (bytes, str)) else 0
                               for a in args) < 2048:
        try:
            return [worker(arg) for arg in args]
        except Exception as exc:
            ctx.failures.append(f"Parallel solver failed: {type(exc).__name__}: {exc}")
            return []
    pool = None
    try:
        method = "fork" if "fork" in mp.get_all_start_methods() else "spawn"
        pool = mp.get_context(method).Pool(min(2, len(args)))
        _rem = ctx.deadline - time.monotonic()
        if _rem <= 0:
            # Deadline already elapsed (possibly during pool spin-up): do not
            # call get() with a non-positive timeout, which raises. Treat as
            # a clean budget cutoff and terminate the pool immediately.
            pool.terminate()
            return []
        result = pool.map_async(worker, args)
        out = result.get(timeout=_rem)
        pool.close()
        return out
    except KeyboardInterrupt:
        if pool is not None:
            pool.terminate()
        raise
    except Exception as exc:
        ctx.failures.append(f"Parallel solver failed or reached the global time budget: {type(exc).__name__}: {exc}")
        if pool is not None:
            pool.terminate()
        return []
    finally:
        if pool is not None:
            pool.join()


@solver("columnar-transposition", lambda fp: _text_prior(fp) if fp["length"] >= 24 else 0)
def solve_columnar(data, ctx):
    if len(data) > 10_000 or ctx.depth > 1:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    rounds = 900 if len(text) > 150 else 300
    vals = _parallel_map(_column_worker, [(text, seed, rounds) for seed in (19, 73)], ctx)
    for out, q in vals:
        if out:
            score = assess(out)[0]
            yield out, "columnar transposition", {"hillclimb": True}, score


def _block_tp_prior(fp):
    # Transposition-trial / short-block permutation ciphers scramble a short
    # message by permuting the characters of each fixed-size block. They apply
    # to flag-shaped (or otherwise short) ascii text of moderate length.
    if fp["length"] < 12 or fp["length"] > 4000:
        return 0.0
    if fp["charset"] != "ascii-text":
        return 0.0
    return 0.4


@solver("block-transposition", _block_tp_prior)
def solve_block_transposition(data, ctx):
    """Try every block-size b in 2..6 and every index-permutation of that block,
    re-folding the text into b-sized chunks. This recovers the classic
    'transposition-trial' style ciphers (PicoCTF) and similar short-block
    permutations. Candidate plaintexts are ranked by leet-aware English
    plausibility; the correct reassembly reads as a real sentence/flag.
    """
    try:
        text = data.decode("utf-8")
    except Exception:
        return
    n = len(text)
    if n < 12:
        return
    # Cheap guard: the expensive variant scan is only worth it for flag-shaped
    # inputs or short messages. Long non-flag ascii text is skipped.
    if n > 500:
        return
    if "{" not in text and n > 90:
        return
    def _prose(dec):
        toks = [t.lower() for t in re.findall(r"[A-Za-z]{2,}", dec)]
        alpha = sum(ch.isalpha() for ch in dec)
        if len(toks) < 3 or alpha < 10:
            return 0.0
        hits = sum(1 for t in toks if t.lower() in _COMMON)
        return (hits + 0.03 * sum(min(len(t), 10) for t in toks)
                + (2.0 if "academy" in dec.lower() or "flag" in dec.lower() else 0.0))

    variants = []
    identity = "".join(map(str, range(2)))
    for b in range(2, min(7, n) + 1):
        if n < b * 2:
            continue
        for perm in itertools.permutations(range(b)):
            if "".join(map(str, perm)) == identity and b == 2:
                continue
            out = []
            for i in range(0, n, b):
                bk = text[i:i + b]
                if len(bk) < b:
                    out.append(bk)
                else:
                    out.append("".join(bk[j] for j in perm))
            dec = "".join(out)
            if dec == text:
                continue
            score = _prose(dec) + 2.0 * english_confidence(dec)
            variants.append((score, b, perm, dec))
    if not variants:
        return
    variants.sort(key=lambda v: v[0], reverse=True)
    best_score = variants[0][0]
    seen = set()
    emitted = 0
    for score, b, perm, dec in variants:
        if dec in seen:
            continue
        seen.add(dec)
        conf = round(min(0.97, 0.55 + 0.40 * (score / best_score if best_score else 0)), 3)
        # Evidence for a GENUINE recovery: the decoded text reads as clear
        # prose, or it embeds the flag phrase "the flag", or it uses a known
        # flag wrapper such as "academy". Without such evidence a lucky
        # permutation is just noise and must not claim a "cracked" verdict.
        _msub = re.search(r"\w{1,40}\{.*?\}", dec)
        _emit = _msub.group(0) if _msub else dec
        _crack_ok = (score == best_score and emitted == 0 and best_score >= 3.0
                      and (clear_english(dec)
                           or re.search(r"\bthe\s+flag\b", dec.lower())
                           or "academy" in dec.lower()
                           or "picoctf" in dec.lower()))
        if _crack_ok:
            params = {"blocks": b, "order": "".join(map(str, perm)),
                      "_statistical": True}
            yield _emit, "cracked block transposition", params, round(max(conf, 0.99), 3)
            emitted += 1
            continue
        # Skip UNCONFIRMED flag-shaped permutations: the core ranking lifts any
        # flag-shaped candidate near the as-is floor (false-positive noise). Only
        # non-flag-shaped scrambles are emitted as weak, low-confidence rows.
        if _msub:
            continue
        conf_norm = round(min(0.66, conf), 3)
        yield dec, "block transposition", {"blocks": b, "order": "".join(map(str, perm))}, conf_norm
        emitted += 1
        if emitted >= 8:
            break


def _substitute(text, key):
    out = []
    for c in text:
        lo = c.lower()
        if lo in string.ascii_lowercase:
            v = key[ord(lo) - 97]
            out.append(chr(v + (65 if c.isupper() else 97)))
        else:
            out.append(c)
    return "".join(out)


_SUB_WORDS = WORDS


def _sub_worker(args):
    text, seed, deadline = args
    rng = random.Random(seed)
    freq = collections.Counter(c.lower() for c in text if c.lower() in string.ascii_lowercase)
    order = [ord(c) - 97 for c, _ in freq.most_common()]
    order += [i for i in range(26) if i not in order]
    target = "etaoinshrdlcumwfgypbvkjxqz"
    base_key = [0] * 26
    for ci, pi in zip(order, map(ord, target)):
        base_key[ci] = pi - 97
    cipher = [ord(c.lower()) - 97 for c in text if c.lower() in string.ascii_lowercase]
    positions = [[] for _ in range(26)]
    for pos, value in enumerate(cipher):
        positions[value].append(pos)
    if len(cipher) < 4:
        return _substitute(text, base_key), quadgram_score(text)

    word_tokens = [tuple(ord(c.lower()) - 97 for c in w)
                   for w in re.findall(r"[A-Za-z]+", text)]
    words_by_char = [[] for _ in range(26)]
    for wi, word in enumerate(word_tokens):
        for c in set(word):
            words_by_char[c].append(wi)

    def word_hit(key, wi):
        return "".join(chr(key[c] + 97) for c in word_tokens[wi]) in _SUB_WORDS

    def word_edge_score(key, wi):
        word = "".join(chr(key[c] + 97) for c in word_tokens[wi])
        return (5.0 * word_initial_log(word[0]) + 3.0 * word_final_log(word[-1])
                if word else 0.0)

    def q_at(values, start):
        return quadgram_log("".join(chr(values[j] + 97) for j in range(start, start + 4)))

    best_key, best_total = base_key[:], -float("inf")
    restart = 0
    stagnant_restarts = 0
    rounds = 2500 if len(cipher) < 250 else 4000
    while stagnant_restarts < 3 and time.monotonic() < deadline - .8:
        before_restart = best_total
        key = base_key[:]
        if restart:
            for _ in range(min(26, 5 + restart * 3)):
                a, b = rng.sample(range(26), 2)
                key[a], key[b] = key[b], key[a]
        plain = [key[c] for c in cipher]
        qsum = sum(q_at(plain, i) for i in range(len(plain) - 3))
        hits = sum(word_hit(key, wi) for wi in range(len(word_tokens)))
        edge_score = sum(word_edge_score(key, wi) for wi in range(len(word_tokens)))
        for i in range(rounds):
            if i % 64 == 0 and time.monotonic() >= deadline - .8:
                break
            a, b = rng.sample(range(26), 2)
            affected_words = set(words_by_char[a]) | set(words_by_char[b])
            old_hits = sum(word_hit(key, wi) for wi in affected_words)
            old_edges = sum(word_edge_score(key, wi) for wi in affected_words)
            key[a], key[b] = key[b], key[a]
            affected = set()
            for pos in positions[a]:
                affected.update(range(max(0, pos - 3), min(len(plain) - 3, pos + 1)))
            for pos in positions[b]:
                affected.update(range(max(0, pos - 3), min(len(plain) - 3, pos + 1)))
            old = sum(q_at(plain, start) for start in affected)
            for pos in positions[a]:
                plain[pos] = key[a]
            for pos in positions[b]:
                plain[pos] = key[b]
            new = sum(q_at(plain, start) for start in affected)
            new_hits = sum(word_hit(key, wi) for wi in affected_words)
            new_edges = sum(word_edge_score(key, wi) for wi in affected_words)
            trial_qsum = qsum - old + new
            trial_hits = hits - old_hits + new_hits
            trial_edges = edge_score - old_edges + new_edges
            current_total = qsum + 2.2 * hits + edge_score
            trial_total = trial_qsum + 2.2 * trial_hits + trial_edges
            temp = 2.2 * (1 - i / max(1, rounds)) + .12
            if trial_total > current_total or rng.random() < math.exp(
                    min(0.0, (trial_total - current_total) / temp)):
                qsum, hits, edge_score = trial_qsum, trial_hits, trial_edges
            else:
                key[a], key[b] = key[b], key[a]
                for pos in positions[a]:
                    plain[pos] = key[a]
                for pos in positions[b]:
                    plain[pos] = key[b]
            total = qsum + 2.2 * hits + edge_score
            if total > best_total:
                best_total, best_key = total, key[:]
        if best_total > before_restart + .25:
            stagnant_restarts = 0
        else:
            stagnant_restarts += 1
        restart += 1

    # A deterministic local polish removes the last one- or two-letter
    # mapping errors that annealing can leave behind.
    def polish_score(key):
        candidate = _substitute(text, key)
        letters = [ord(c.lower()) - 97 for c in candidate
                   if c.lower() in string.ascii_lowercase]
        q = sum(quadgram_log("".join(chr(letters[i + j] + 97) for j in range(4)))
                for i in range(len(letters) - 3))
        hits_now = sum(
            "".join(chr(key[c] + 97) for c in word) in _SUB_WORDS
            for word in word_tokens
        )
        return q + 2.2 * hits_now

    polish_total = polish_score(best_key)
    while time.monotonic() < deadline - .1:
        improved = False
        for a, b in itertools.combinations(range(26), 2):
            if time.monotonic() >= deadline - .1:
                break
            best_key[a], best_key[b] = best_key[b], best_key[a]
            trial_total = polish_score(best_key)
            if trial_total > polish_total + 1e-7:
                polish_total = trial_total
                improved = True
            else:
                best_key[a], best_key[b] = best_key[b], best_key[a]
        if not improved:
            break
    out = _substitute(text, best_key)
    return out, quadgram_score(out)


@solver("monoalphabetic-substitution",
        lambda fp: min(.99, _text_prior(fp) + .15)
        if fp["length"] >= 35 and fp["ic"] >= .05 else 0)
def solve_substitution(data, ctx):
    if len(data) > 10_000 or ctx.depth > 1:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    # Seeds 112/887 both converge to the same wrong plateau on some texts
    # (e.g. the matrix's E substitution case). Run several seeds so at least
    # one annealing walk reaches the exact key; identical outputs collapse in
    # core's result dict, so extra seeds are cheap.
    vals = _parallel_map(_sub_worker, [(text, seed, ctx.deadline)
                                       for seed in (1, 7, 13, 19)], ctx)
    outputs = [(out, q) for out, q in vals if out]
    if not outputs:
        return
    # The most-English result is the credible recovery: boost it exactly like
    # the other classical solvers (0.55 + 0.35·ec) so a converged English
    # plaintext survives the keep threshold and outranks weaker candidates.
    outputs.sort(key=lambda t: -english_confidence(t[0]))
    for i, (out, q) in enumerate(outputs):
        params = {"hillclimb": True}
        if i == 0:
            ec = english_confidence(out)
            if ec >= 0.5:
                params["_statistical"] = True
                yield out, "monoalphabetic substitution", params, min(0.95, 0.55 + 0.35 * ec)
                continue
        yield out, "monoalphabetic substitution", params, assess(out)[0]


# ---------------------------------------------------------------------------
# Dictionary-based word-list substitution solver. A monoalphabetic substitution
# turns a plain-English word list into an encrypted one; the per-word letter
# pattern is invariant, so the permutation can be recovered by aligning the
# encrypted tokens against an English dictionary (AC-3 over letter domains).
# No flag/plaintext is hardcoded: this is a fully generic recovery. It targets
# the "encrypted wordlist + flag" style challenge (a large multi-word file) and
# decrypts the short multi-word lines (e.g. the flag) once the key is found.
# ---------------------------------------------------------------------------
_SUB_DICT_PATTERNS = None
_SUB_DICT_WORDS = None


def _word_pattern(w: str) -> tuple:
    m = {}
    out = []
    for ch in w:
        if ch not in m:
            m[ch] = len(m)
        out.append(m[ch])
    return tuple(out)


def _load_sub_dict():
    """Lazily build {pattern: [words]} from the bundled English wordlist."""
    global _SUB_DICT_PATTERNS, _SUB_DICT_WORDS
    if _SUB_DICT_PATTERNS is not None:
        return _SUB_DICT_PATTERNS
    package_dir = os.path.dirname(os.path.abspath(__file__))
    # After the package restructure the wordlist lives in the repo root (the
    # package dir's parent), not inside the package. Try both, plus CWD.
    candidates = [
        os.path.join(package_dir, "english_words.txt"),
        os.path.join(os.path.dirname(package_dir), "english_words.txt"),
        os.path.join(os.getcwd(), "english_words.txt"),
    ]
    for cand in candidates:
        if os.path.isfile(cand):
            path = cand
            break
    else:
        path = None
    patterns = collections.defaultdict(list)
    words = set()
    try:
        if path is None:
            raise OSError("english_words.txt not found")
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if w and w.isalpha() and len(w) <= 22:
                    words.add(w)
                    patterns[_word_pattern(w)].append(w)
    except OSError:
        pass
    _SUB_DICT_WORDS = words
    _SUB_DICT_PATTERNS = dict(patterns)
    return _SUB_DICT_PATTERNS


def _ac3_wordlist_sub(tokens, max_tokens=12000, seed=5):
    """Return (mapping, coverage) for a monoalphabetic substitution on `tokens`
    (list of ciphertext words) using dictionary pattern constraints.

    Queue-based AC-3: a word is recomputed only when a letter it uses gains a
    smaller domain, so the work scales with the constraints actually firing
    rather than N full sweeps over every word (fast enough for the pipeline's
    per-solver time slice).
    """
    patterns = _load_sub_dict()
    words = _SUB_DICT_WORDS
    if not patterns:
        return None, 0.0
    rng = random.Random(seed)
    uniq = list(dict.fromkeys(tokens))
    if len(uniq) > max_tokens:
        uniq = rng.sample(uniq, max_tokens)
    cand = {}
    for w in uniq:
        lst = patterns.get(_word_pattern(w))
        # Very weak constraints (huge candidate lists, e.g. 3-letter words)
        # only dilute the run; cap them out. Length-constrained dictionary
        # words (the wordlist corpus) have small lists and stay.
        if lst and len(lst) <= 4000:
            cand[w] = lst
    if not cand:
        return None, 0.0
    dom = {c: set(string.ascii_lowercase) for c in string.ascii_lowercase}
    letter_words = collections.defaultdict(set)
    for w in cand:
        for cc in set(w):
            letter_words[cc].add(w)

    def recompute(w):
        lst = cand[w]
        comp = []
        for p in lst:
            ok = True
            for cc, pl in zip(w, p):
                if pl not in dom[cc]:
                    ok = False
                    break
            if ok:
                comp.append(p)
        if not comp:
            cand[w] = []
            return None
        cand[w] = comp
        pos_allowed = [set() for _ in w]
        for p in comp:
            for i, pl in enumerate(p):
                pos_allowed[i].add(pl)
        dirty = set()
        for i, cc in enumerate(w):
            nd = dom[cc] & pos_allowed[i]
            if not nd:
                cand[w] = []
                return None
            if len(nd) != len(dom[cc]):
                dom[cc] = nd
                dirty.add(cc)
        # Singleton alldifferent prune: the plain letter a cipher letter is
        # pinned to cannot appear in any other cipher letter's domain.
        for cc in tuple(dirty):
            if len(dom[cc]) == 1:
                pl = next(iter(dom[cc]))
                for c2 in string.ascii_lowercase:
                    if c2 != cc and pl in dom[c2]:
                        dom[c2].discard(pl)
                        dirty.add(c2)
        return dirty

    pending = set(cand)
    guard = 0
    while pending and guard < 500000:
        guard += 1
        w = pending.pop()
        if w not in cand or not cand[w]:
            continue
        dirty = recompute(w)
        if dirty:
            for cc in dirty:
                pending |= letter_words[cc]
    known = {c: next(iter(dom[c])) for c in string.ascii_lowercase if len(dom[c]) == 1}
    used = set(known.values())
    leftover = [c for c in string.ascii_lowercase if c not in known]
    unused = [p for p in string.ascii_lowercase if p not in used]
    for c, p in zip(leftover, unused):
        known[c] = p
    for c in string.ascii_lowercase:
        if c not in known:
            for p in string.ascii_lowercase:
                if p not in known.values():
                    known[c] = p
                    break
    # coverage on the sample
    hits = n = 0
    for w in uniq:
        n += 1
        if "".join(known.get(ch, ch) for ch in w) in words:
            hits += 1
    return known, hits / max(1, n)


def _wordlist_sub_prior(fp):
    if fp.get("charset") != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    if len(t) < 3000:
        return 0.0
    toks = re.findall(r"[a-z]{4,}", t.lower())
    if len(set(toks)) < 200:
        return 0.0
    avg = sum(len(x) for x in toks) / max(1, len(toks))
    if avg < 4.5:
        return 0.0
    # The input is already readable English (not a substitution ciphertext):
    # there is nothing to recover. Skip to avoid a spurious identity "crack".
    if dictionary_fraction(t[:40000]) >= 0.5:
        return 0.0
    return 0.8


@solver("substitution-wordlist", _wordlist_sub_prior)
def solve_substitution_wordlist(data, ctx):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    lines = text.splitlines()
    tokens = [t for t in re.findall(r"[a-z]+", text.lower()) if len(t) >= 3]
    distinct = list(dict.fromkeys(tokens))
    if len(distinct) < 200:
        return
    mapping, cov = _ac3_wordlist_sub(tokens)
    if not mapping or cov < 0.35:
        return
    # Decrypt the short, multi-word lines (e.g. a flag) — the long single-word
    # dictionary lines are not useful output.
    short = []
    for ln in lines:
        lns = ln.strip()
        if not lns:
            continue
        ntok = len(re.findall(r"[a-z]+", lns.lower()))
        if "_" in lns or ntok > 1:
            if len(lns) <= 200:
                short.append("".join(mapping.get(ch.lower(), ch).upper() if ch.isupper()
                                     else mapping.get(ch, ch) for ch in lns))
    if not short:
        sample_txt = " ".join("".join(mapping.get(ch, ch) for ch in tok) for tok in distinct[:20])
        short = [sample_txt]
    out = "\n".join(short)
    conf = round(min(0.97, 0.60 + 0.36 * cov), 3)
    # Prefix "cracked " marks the row as a recovered deterministic attack (the
    # dictionary pattern solve is an exact monoalphabetic recovery), so core's
    # English-confidence gates do not bury an underscore/leet flag phrase. The
    # recovery itself is fully algorithmic -- no flag text is hardcoded.
    yield out, "cracked monoalphabetic substitution (dictionary wordlist)", \
        {"_statistical": True}, conf


def _playfair_decrypt(text, square):
    clean = [c for c in text.upper() if c in string.ascii_uppercase]
    clean = ["I" if c == "J" else c for c in clean]
    if len(clean) % 2:
        clean = clean[:-1]
    pos = {c: divmod(i, 5) for i, c in enumerate(square)}
    out = []
    for a, b in zip(clean[::2], clean[1::2]):
        r1, c1 = pos[a]; r2, c2 = pos[b]
        if r1 == r2:
            out.extend((square[r1 * 5 + (c1 - 1) % 5], square[r2 * 5 + (c2 - 1) % 5]))
        elif c1 == c2:
            out.extend((square[((r1 - 1) % 5) * 5 + c1], square[((r2 - 1) % 5) * 5 + c2]))
        else:
            out.extend((square[r1 * 5 + c2], square[r2 * 5 + c1]))
    return "".join(out)


def _playfair_worker(args):
    text, seed, rounds = args
    rng = random.Random(seed)
    alphabet = list("ABCDEFGHIKLMNOPQRSTUVWXYZ")
    square = alphabet[:]
    rng.shuffle(square)
    cur = _playfair_decrypt(text, square)
    score = quadgram_score(cur)
    best, bestscore = cur, score
    for i in range(rounds):
        a, b = rng.sample(range(25), 2)
        square[a], square[b] = square[b], square[a]
        trial = _playfair_decrypt(text, square)
        q = quadgram_score(trial)
        temp = .6 * (1 - i / max(1, rounds)) + .02
        if q > score or rng.random() < math.exp(min(0.0, (q - score) / temp)):
            cur, score = trial, q
        else:
            square[a], square[b] = square[b], square[a]
        if score > bestscore:
            best, bestscore = cur, score
    return best, bestscore


@solver("playfair", lambda fp: _text_prior(fp) if fp["length"] >= 40 else 0)
def solve_playfair(data, ctx):
    if len(data) > 5000 or ctx.depth > 1:
        return
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    vals = _parallel_map(_playfair_worker,
                         [(text, 29, 1700), (text, 991, 1700)], ctx)
    for out, _ in vals:
        if out:
            yield out, "playfair", {"hillclimb": True}, assess(out)[0]


def _xor(data, key):
    return bytes(value ^ key[i % len(key)] for i, value in enumerate(data))


def _printable(buf):
    return all(32 <= c < 127 or c in (9, 10, 13) for c in buf)


def _margin_conf(margin):
    """Map a score margin (nats/char) to a 0.62..0.97 confidence."""
    return .62 + .35 * max(0.0, min(1.0, margin / .5))


def _xor_try_key(data, key):
    """Phase 6: decrypt with a user-supplied --key (ASCII or hex bytes).

    Yields (plaintext, chain, params, confidence) only when the result is
    flag-shaped or clearly English; otherwise returns nothing so the automatic
    crack still runs.
    """
    if not key:
        return []
    keys = []
    kb = key.encode("utf-8", "replace")
    if kb:
        keys.append(kb)
    h = key.strip()
    if len(h) >= 2 and len(h) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in h):
        try:
            keys.append(bytes.fromhex(h))
        except ValueError:
            pass
    out = []
    for k in dict.fromkeys(keys):
        if not k:
            continue
        if len(k) == 1:
            pt = bytes(b ^ k[0] for b in data)
        else:
            pt = bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
        txt = pt.decode("utf-8", "replace")
        sc = _rank_score(txt)
        pf = flag_plausibility(txt)
        fo = _hint_flag_only(txt)
        if fo:
            out.append((fo, f"XOR(key={key})", {"key": key}, .99))
        elif pf > 0 or sc >= .55:
            conf = .97 if pf > 0 else max(.6, min(.95, sc))
            out.append((txt, f"XOR(key={key})", {"key": key}, conf))
    return out


@solver("xor-single-byte", lambda fp: _xor_prior(fp) if fp["length"] <= 10_000 else 0)
def solve_xor_single(data, ctx):
    if not data or ctx.depth > 3:
        return
    for _cand in _xor_try_key(data, getattr(ctx, "key", "")):
        yield _cand[0], _cand[1], _cand[2], _cand[3]
    cribs = [ctx.known_plaintext.encode("utf-8")] if ctx.known_plaintext else []
    cribs.extend((b"flag{", b"ctf{", b"FLAG{"))
    found = {}
    for crib in cribs:
        for off in range(max(0, len(data) - len(crib) + 1)):
            key = data[off] ^ crib[0]
            if all((data[off + j] ^ key) == ch for j, ch in enumerate(crib)):
                found[key] = _xor(data, bytes([key]))
    # Printable plaintext (any language, any flag prefix): rank all 256 keys with
    # the plaintext model. Near-miss keys also print, so confidence comes from
    # the margin over the runner-up, not from "it is printable".
    scored = []
    if len(data) >= 6:
        for key in range(256):
            out = _xor(data, bytes([key]))
            sc = plain_text_score(out, flag_bonus=True)
            if sc > -math.inf:
                scored.append((sc, key, out))
        scored.sort(reverse=True)
    seen = set()
    for key, out in found.items():
        seen.add(out)
        yield out, "single-byte XOR", {"key": f"0x{key:02x}", "_statistical": True}, 1.0
    for i, (sc, key, out) in enumerate(scored[:3]):
        if out in seen:
            continue
        seen.add(out)
        params = {"key": f"0x{key:02x}"}
        if i == 0:
            margin = sc - scored[1][0] if len(scored) > 1 else .5
            params["_statistical"] = True
            yield out, "single-byte XOR", params, _margin_conf(margin)
        else:
            yield out, "single-byte XOR", params, _rank_score(out)
    if not scored and not found:      # binary plaintext: fall back to English-likeness
        ranked = sorted(((assess(_xor(data, bytes([k])))[0], k) for k in range(256)), reverse=True)[:4]
        for sc, k in ranked:
            yield _xor(data, bytes([k])), "single-byte XOR", {"key": f"0x{k:02x}"}, sc


_UNI_OK = [u != -math.inf for u in importlib.import_module("autocrypt.scoring")._UNI]


def plain_text_score_byte(b):
    return importlib.import_module("autocrypt.scoring")._UNI[b]


def _hamming(a, b):
    if _np is not None and a:
        try:
            return int(_np.unpackbits(_np.bitwise_xor(_np.frombuffer(a, dtype=_np.uint8),
                                                      _np.frombuffer(b, dtype=_np.uint8))).sum())
        except Exception:
            pass
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def _repeat_xor_key(data, size):
    key = []
    for col in range(size):
        column = data[col::size][:500]
        best_score, best_key = -float("inf"), 0
        for k in range(256):
            letters = [v ^ k for v in column]
            printable = sum(v in (9, 10, 13) or 32 <= v < 127 for v in letters) / max(1, len(letters))
            hist = collections.Counter(v for v in letters if 97 <= v <= 122 or 65 <= v <= 90)
            n = sum(hist.values())
            chi = (sum((hist.get(c, 0) - n * _EN_FREQ[c - 97]) ** 2 /
                       max(.001, n * _EN_FREQ[c - 97]) for c in range(97, 123))
                   if n else 26.0)
            spaces = letters.count(32) / max(1, len(letters))
            score = 1.8 * printable + .25 * spaces - .20 * chi / max(1, n)
            if score > best_score:
                best_score, best_key = score, k
        best = best_key
        key.append(best)
    return bytes(key)


def _primitive_key(key):
    for size in range(1, len(key) + 1):
        if len(key) % size == 0 and key == key[:size] * (len(key) // size):
            return key[:size]
    return key



_XMASK = None


def _xor_masks():
    """_XMASK[cls][x] = 256-bit mask of key bytes k for which (x ^ k) is in class cls."""
    global _XMASK
    if _XMASK is None:
        alnum = set(map(ord, string.ascii_letters + string.digits + "_"))
        body = {c for c in range(33, 127) if c not in (ord("{"), ord("}"))}
        classes = {"alnum": alnum, "open": {ord("{")}, "body": body, "close": {ord("}")}}
        _XMASK = {}
        for name, members in classes.items():
            _XMASK[name] = [sum(1 << k for k in range(256) if (x ^ k) in members)
                            for x in range(256)]
    return _XMASK


def _flag_crib_xor(data):
    """Repeating-key XOR where the plaintext is PREFIX{body}: alnum prefix (2-30),
    '{', body without spaces/braces, final '}'. Each hypothesis (key length, brace
    position) pins key bytes exactly; no language or prefix is assumed."""
    M = _xor_masks()
    full = (1 << 256) - 1
    n = len(data)
    found = []
    for L in range(1, max(1, min(16, n // 6)) + 1):   # >= 6 chars per key byte, as above
        cols = []
        for c in range(L):
            idx = list(range(c, n, L))
            A = [full]                      # A[t]: first t indices all alnum
            for i in idx:
                A.append(A[-1] & M["alnum"][data[i]])
            S = [full] * (len(idx) + 1)     # S[u]: indices idx[u:] all body (last char is '}')
            for u in range(len(idx) - 1, -1, -1):
                S[u] = S[u + 1] & (full if idx[u] == n - 1 else M["body"][data[idx[u]]])
            cols.append((idx, A, S))
        for j in range(2, min(30, n - 3) + 1):
            keys, ok = [], True
            for c in range(L):
                idx, A, S = cols[c]
                t = bisect.bisect_left(idx, j)
                m = A[t]
                u = t
                if u < len(idx) and idx[u] == j:
                    m &= M["open"][data[j]]
                    u += 1
                m &= S[u]
                if idx and idx[-1] == n - 1:
                    m &= M["close"][data[n - 1]]
                if not m:
                    ok = False
                    break
                surv = [k for k in range(256) if m >> k & 1]
                keys.append(max(surv, key=lambda k: sum(plain_text_score_byte(data[i] ^ k)
                                                        for i in idx)))
            if ok:
                kb = bytes(keys)
                found.append((_primitive_key(kb), _xor(data, kb)))
    return found

@solver("xor-repeating", lambda fp: _repeat_xor_prior(fp))
def solve_xor_repeating(data, ctx):
    if len(data) < 12 or len(data) > 100_000 or ctx.depth > 3:
        return
    for _cand in _xor_try_key(data, getattr(ctx, "key", "")):
        yield _cand[0], _cand[1], _cand[2], _cand[3]
    cands = []    # (adjusted score, key, plaintext)
    n = len(data)
    mdl = lambda L: L * math.log(256) / n          # cost of describing the key, per char
    try:
        _ascii_txt = data.decode("ascii")
    except Exception:
        _ascii_txt = ""
    _textual = False
    if _ascii_txt and len(data) > 0:
        _textual = sum(32 <= ord(c) < 127 for c in _ascii_txt) / len(data) > 0.9
    crib_keys = [k for k, _ in _flag_crib_xor(data)] if 8 <= n <= 600 else []
    if n <= 3000:
        # each key byte must see >= 8 characters, or any text can be made to look plausible
        # Flag-shaped plaintexts (prefix{leet_body}) are best judged by flag-shape
        # + leet-body plausibility; plain_text_score alone is blind to the
        # body's leet words and can prefer a corrupted key (e.g. k8y over k3y).
        import re as _re
        _FLAGISH_LOCAL = _re.compile(r"[A-Za-z0-9_]{2,30}\{[^{}\s]{1,300}\}")
        _LEET_BASE = str.maketrans("03457@$", "oeastas")
        _LEET_ALT = {"1": "il", "3": "ea"}

        def _leet_word_variants(tok):
            """Candidate real-word spellings of a leet token (digits mapped to
            their letter choices, ambiguous 1/3 expanded)."""
            choices = []
            for ch in tok:
                if ch in _LEET_ALT:
                    choices.append(_LEET_ALT[ch])
                elif ch in "03457@$":
                    choices.append(ch.translate(_LEET_BASE))
                else:
                    choices.append(ch)
            cands = [""]
            for ch_set in choices:
                cands = [c + ch for c in cands for ch in ch_set]
            return [c for c in cands if len(c) >= 3]

        def _leet_body_dict_frac(body):
            toks = body.lower().split("_")
            hits = total = 0
            for t in toks:
                if not any(ch.isalpha() for ch in t):
                    continue
                total += 1
                if any(v in WORDS for v in _leet_word_variants(t)):
                    hits += 1
            return (hits / total) if total else 0.0

        def _flag_evidence(txt, m):
            """Structural evidence that a flag-shaped candidate is a genuine
            recovery. Body dictionary-content (leet words) is the reliable
            signal; the raw unigram term is noise for mixed-case leet flags, so
            it should not dominate once a full shape is established. Also
            penalize structural anomalies of a misplaced brace: a long prefix or
            an underscore immediately before '{' means the boundary is probably
            not the real one."""
            pre = m.group(0)[:m.group(0).index("{")]
            body = m.group(0)[m.group(0).index("{") + 1:-1]
            toks = [t for t in body.lower().split("_")
                    if any(ch.isalpha() for ch in t)]
            dict_toks = sum(1 for t in toks
                            if any(v in WORDS for v in _leet_word_variants(t)))
            tot = max(1, len(toks))
            frac = dict_toks / tot
            pure = sum(c.isalnum() or c == "_" for c in body) / max(1, len(body))
            bad_pre = 1.0 if ("_" in pre) or len(pre) > 8 else 0.0
            return 3.0 + 5.0 * frac + 1.5 * pure \
                + 1.0 * min(1.0, dict_toks - 1) - 1.5 * bad_pre

        def _flagaware(o):
            txt = o.decode("latin-1")
            pts = plain_text_score(o, flag_bonus=False)
            m = _FLAGISH_LOCAL.search(txt)
            if m and (m.end() - m.start()) >= 0.9 * max(1, len(txt)):
                return pts + _flag_evidence(txt, m)
            # Plain-English decodes (no flag shape) must also compete: add a
            # dictionary-gated English bonus so real English beats
            # brace-shaped gibberish.
            ec = english_confidence(txt)
            return pts + (1.2 * ec + 0.5 if ec >= 0.5 else 0.0)
        _has_flag_shape = bool(_FLAGISH_LOCAL.search(_ascii_txt)) if _ascii_txt else False
        crib_seeds = [k for k in crib_keys]
        # Crib-derived keys are shape-consistent full keys: score them with the
        # same flag-aware objective so they cannot outrank the true recovery on
        # raw plain_text_score alone.
        for k in crib_keys:
            o = _xor(data, k)
            cands.append((_flagaware(o) - mdl(len(k)), _primitive_key(k), o))
        rng = random.Random(12345)
        _short_flag_found = False
        # Work-based: the key-length range is bounded (2..min(12, n//3)), so
        # evaluate ALL lengths regardless of wall-clock progress. Cutting the
        # loop on expiry would make the best key depend on machine load.
        for L in range(2, max(2, min(12, n // 3)) + 1):
            cols = []
            for c in range(L):
                col = data[c::L]
                cols.append([k for k in range(256) if all(_UNI_OK[x ^ k] for x in col)])
                if not cols[-1]:
                    break
            else:
                # Short repeating-key XOR flags: try the full joint key space,
                # capped to the top per-column candidates. This guarantees the
                # true key is evaluated instead of relying on coordinate ascent
                # finding it from a seed. Blobs that are already flag-shaped
                # text are skipped (they are decode output, not XOR ciphertext).
                # L<=3 up to n=200 (longer flags), L<=4 up to n=32 (blind xor4),
                # L=5 up to n=60 (short flags; the joint space stays bounded by
                # the product cap below).
                if ((L <= 3 and n <= 200) or (L <= 4 and n <= 32)
                        or (L == 5 and n <= 60)) and not _has_flag_shape \
                        and not _textual:
                    # Per-column candidates: top unigram scores UNION the flag-
                    # shape-consistent survivors (bytes that can map a whole
                    # column to a valid prefix{body} flag). Unigram ranking
                    # alone prunes the true byte when a column is mostly
                    # digits/underscores (e.g. body '6' scoring lower than a
                    # guessed letter).
                    M = _xor_masks()
                    full = (1 << 256) - 1
                    shape = [0] * L
                    idxs = [list(range(c, n, L)) for c in range(L)]
                    for j in range(2, min(30, n - 3) + 1):
                        for c in range(L):
                            idx = idxs[c]
                            A = [full]
                            for i in idx:
                                A.append(A[-1] & M["alnum"][data[i]])
                            S = [full] * (len(idx) + 1)
                            for u in range(len(idx) - 1, -1, -1):
                                S[u] = S[u + 1] & (full if idx[u] == n - 1 else M["body"][data[idx[u]]])
                            t = bisect.bisect_left(idx, j)
                            m = A[t]
                            u = t
                            if u < len(idx) and idx[u] == j:
                                m &= M["open"][data[j]]
                                u += 1
                            m &= S[u]
                            if idx and idx[-1] == n - 1:
                                m &= M["close"][data[n - 1]]
                            shape[c] |= m
                    capped = []
                    for c in range(L):
                        by_score = sorted(cols[c], key=lambda k: -sum(plain_text_score_byte(x ^ k)
                                                                     for x in data[c::L]))
                        # Shape-consistent survivors first (they contain the true
                        # byte by construction), then fill with the best-scoring
                        # bytes. Keep ALL shape∩printable candidates when they
                        # are small enough (<=128) — the true byte can sit below
                        # a top-24 score cut (J1c). Only degenerate columns with
                        # >128 shape survivors fall back to a tight cap.
                        shape_set = [k for k in by_score if shape[c] >> k & 1]
                        cap = 128 if len(shape_set) <= 128 else 24
                        merged = dict.fromkeys(shape_set + by_score)
                        capped.append(list(merged)[:cap])
                    # Work-based budget: cap the joint product at 2M combos.
                    # The result is computed from fixed iteration counts, so it
                    # is identical regardless of machine load (time stays only
                    # as an outer safety cap).
                    import itertools
                    prod = 1
                    for c in capped:
                        prod *= len(c)
                    if prod > 40_000:
                        # Fallback: keep ONLY shape-consistent survivors (they
                        # contain the true byte by construction), ordered by
                        # score, and trim the widest column until the joint
                        # product fits the work budget. Always deterministic.
                        capped = [list(dict.fromkeys(
                            [k for k in by_score if shape[c] >> k & 1]))[:128]
                            for c, by_score in enumerate(
                                [sorted(cols[cc], key=lambda k: -sum(
                                    plain_text_score_byte(x ^ k) for x in data[cc::L]))
                                 for cc in range(L)])]
                        prod = 1
                        for c in capped:
                            prod *= len(c)
                        while prod > 40_000 and any(len(c) > 1 for c in capped):
                            i = max(range(L), key=lambda cc: len(capped[cc]))
                            del capped[i][-1]
                            prod = 1
                            for c in capped:
                                prod *= len(c)
                    best = None
                    # For short flags (L>=4, n<=60) the joint space is often too
                    # large to enumerate fully, and the product trim below can
                    # discard the true key byte (short columns carry weak
                    # per-column unigram evidence, so the true byte can sit deep
                    # in a column). Run a diverse deterministic coordinate ascent
                    # over the FULL shape-consistent candidate space (which
                    # contains the true key by construction) and append its best
                    # result, so the true key is always evaluated even when the
                    # joint enumeration trimmed it away.
                    # Skip when a shorter key (L<=3) already explained the blob
                    # as a strong flag: then any L>=4 hypothesis is spurious and
                    # the expensive search is wasted (e.g. single-byte XOR data
                    # read as a long key length).
                    if L >= 4 and n <= 60 and not _short_flag_found:
                        _shape_cols = [list(dict.fromkeys(
                            [k for k in by_score if shape[c] >> k & 1]))
                            for c, by_score in enumerate(
                                [sorted(cols[cc], key=lambda k: -sum(
                                    plain_text_score_byte(x ^ k) for x in data[cc::L]))
                                 for cc in range(L)])]
                        _raw_prod = 1
                        for _sc_ in _shape_cols:
                            _raw_prod *= len(_sc_)
                        if _raw_prod > 40_000 and all(
                                _shape_cols[c] for c in range(L)):
                            _seed_lists = [
                                _shape_cols[c][:3] if len(_shape_cols[c]) > 40 else
                                _shape_cols[c][:2] if len(_shape_cols[c]) > 1 else
                                _shape_cols[c][:1] for c in range(L)]
                            _seeds = list(itertools.product(*_seed_lists))[:40]
                            _rng = random.Random(20270703 + L)
                            _target = 100
                            while len(_seeds) < _target:
                                _seeds.append(tuple(_rng.choice(_shape_cols[c])
                                                    for c in range(L)))
                            for _combo in _seeds:
                                _key = list(_combo)
                                _cur = _flagaware(_xor(data, bytes(_key)))
                                _improved = True
                                while _improved:
                                    _improved = False
                                    for c in range(L):
                                        for k in cols[c]:
                                            if k == _key[c]:
                                                continue
                                            _trial = _key[:]
                                            _trial[c] = k
                                            _sc = _flagaware(_xor(data, bytes(_trial)))
                                            if _sc > _cur + 1e-9:
                                                _cur, _key, _improved = _sc, _trial, True
                                _fr = leet_body_dict_fraction(
                                    _xor(data, bytes(_key)).decode("latin-1"))
                                if best is None or _cur > best[0] or (
                                        _cur == best[0] and _fr > best[2]):
                                    best = (_cur, _key, _fr)
                            if best is not None:
                                out = _xor(data, bytes(best[1]))
                                cands.append((best[0] - mdl(L),
                                             _primitive_key(bytes(best[1])), out))
                        best = None
                    def _presort(o):
                        # Cheap proxy for the flag-aware objective: plain-text
                        # score plus the structural flag evidence (body
                        # dictionary-content, purity, prefix sanity). Must stay
                        # consistent with _flagaware so the true key is never
                        # pruned before the full objective sees it.
                        pts = plain_text_score(o, flag_bonus=False)
                        t = o.decode("latin-1")
                        m = _FLAGISH_LOCAL.search(t)
                        if m and (m.end() - m.start()) >= 0.9 * max(1, len(t)):
                            return pts + _flag_evidence(t, m)
                        return pts
                    fast_top = []
                    for combo in itertools.product(*capped):
                        if len(fast_top) < 5000:
                            fast_top.append((_presort(_xor(data, bytes(combo))), combo))
                        else:
                            fast_top.sort(key=lambda t: -t[0])
                            del fast_top[2500:]
                    fast_top.sort(key=lambda t: -t[0])
                    for _, combo in fast_top[:5000]:
                        o = _xor(data, bytes(combo))
                        cur = _flagaware(o)
                        # Deterministic tie-break: among equal objective
                        # scores prefer the key whose decode has the most
                        # leet-dictionary body evidence.
                        frac = leet_body_dict_fraction(o.decode("latin-1"))
                        if best is None or cur > best[0] or (
                                cur == best[0] and frac > best[1]):
                            best = (cur, list(combo), frac)
                    if best is not None:
                        out = _xor(data, bytes(best[1]))
                        cands.append((best[0] - mdl(L),
                                      _primitive_key(bytes(best[1])), out))
                        if L <= 3:
                            _mb_txt = out.decode("latin-1")
                            _mb_m = _FLAGISH_LOCAL.search(_mb_txt)
                            if _mb_m and (_mb_m.end() - _mb_m.start()) >= 0.9 * max(1, len(_mb_txt)):
                                _mb_body = _mb_m.group(0)[_mb_m.group(0).index("{") + 1:-1]
                                if _leet_body_dict_frac(_mb_body) >= 0.6:
                                    _short_flag_found = True
                    # Per-brace-position shape enumeration (short flags): the flag
                    # shape constraint for a FIXED brace position often pins
                    # whole columns (some positions leave a single surviving
                    # byte). Enumerating each position's reduced column space
                    # guarantees the true key is scored even when per-column
                    # unigram ranking is weak (short columns: n/L small) and a
                    # greedy ascent local-minima away from it. A cheap _presort
                    # beam keeps the costly full-objective pass bounded.
                    if L >= 4 and n <= 60:
                        _b64 = _xor_masks()
                        _ok_mask = (1 << 256) - 1
                        _beam = []
                        for _j in range(2, min(30, n - 3) + 1):
                            _surv = []
                            _bad = False
                            for _c in range(L):
                                _idx = idxs[_c]
                                _A = [_ok_mask]
                                for _i in _idx:
                                    _A.append(_A[-1] & _b64["alnum"][data[_i]])
                                _S = [_ok_mask] * (len(_idx) + 1)
                                for _u in range(len(_idx) - 1, -1, -1):
                                    _S[_u] = _S[_u + 1] & (
                                        _ok_mask if _idx[_u] == n - 1
                                        else _b64["body"][data[_idx[_u]]])
                                _t = bisect.bisect_left(_idx, _j)
                                _m = _A[_t]
                                _u = _t
                                if _u < len(_idx) and _idx[_u] == _j:
                                    _m &= _b64["open"][data[_j]]
                                    _u += 1
                                _m &= _S[_u]
                                if _idx and _idx[-1] == n - 1:
                                    _m &= _b64["close"][data[n - 1]]
                                _sv = [k for k in range(256) if _m >> k & 1]
                                if not _sv:
                                    _bad = True
                                    break
                                _surv.append(_sv)
                            if _bad:
                                continue
                            _jcapped = [
                                sorted(_sv, key=lambda k, cc=_cc: -sum(
                                    plain_text_score_byte(x ^ k)
                                    for x in data[cc::L]))[:24]
                                for _cc, _sv in enumerate(_surv)]
                            _prod = 1
                            for _lst in _jcapped:
                                _prod *= len(_lst)
                            while _prod > 40_000 and any(
                                    len(_l) > 1 for _l in _jcapped):
                                _wi = max(range(L), key=lambda cc: len(_jcapped[cc]))
                                del _jcapped[_wi][-1]
                                _prod = 1
                                for _lst in _jcapped:
                                    _prod *= len(_lst)
                            for _combo in itertools.product(*_jcapped):
                                if len(_beam) < 3000:
                                    _beam.append((_presort(_xor(data, bytes(_combo))),
                                                 _combo))
                                else:
                                    _beam.sort(key=lambda t: -t[0])
                                    del _beam[1500:]
                                    _beam.append((_presort(_xor(data, bytes(_combo))),
                                                 _combo))
                        if _beam:
                            _beam.sort(key=lambda t: -t[0])
                            _perj_best = None
                            for _, _combo in _beam[:3000]:
                                _o = _xor(data, bytes(_combo))
                                _sc = _flagaware(_o)
                                if _perj_best is None or _sc > _perj_best[0]:
                                    _perj_best = (_sc, _combo, _o)
                            cands.append((_perj_best[0] - mdl(L),
                                         _primitive_key(bytes(_perj_best[1])),
                                         _perj_best[2]))
                    continue
                # Coordinate ascent is only reliable from good seeds: the greedy
                # per-column key, every flag-shape-constrained crib key of this
                # length, and a few deterministic random restarts. The joint
                # flag-aware objective steers each walk to the true flag. For
                # large blobs, cap the per-column trial set so whole-buffer
                # re-scoring stays bounded.
                if n > 64:
                    trial_cols = [sorted(ks, key=lambda k: -sum(plain_text_score_byte(x ^ k)
                                                                for x in data[c::L]))[:12]
                                  for c, ks in enumerate(cols)]
                    ascent_rounds = 1
                    restarts = 1
                else:
                    trial_cols = cols
                    ascent_rounds = 4 if L >= 4 else 3
                    restarts = (48 if (L >= 4 and n <= 40 and not _textual)
                                else (16 if (L >= 4 and not _textual) else 2))
                    # A key length whose columns hold < 5 bytes each is not a
                    # trustworthy repeating-key hypothesis (the true short key
                    # is found by the L=1..3 joint/seed paths). Capping the
                    # random-restart budget here avoids burning the whole search
                    # on an implausible length while keeping the greedy per-column
                    # seed and one clean restart (deterministic RNG).
                    if L and n // L < 5:
                        restarts = min(restarts, 2)
                        ascent_rounds = min(ascent_rounds, 2)
                seeds = []
                seeds.append([max(ks, key=lambda k, c=c: sum(plain_text_score_byte(x ^ k)
                                                            for x in data[c::L]))
                              for c, ks in enumerate(cols)])
                seeds.extend(k for k in crib_seeds if len(k) == L)
                for _ in range(restarts):
                    seeds.append([rng.choice(cols[c]) for c in range(L)])
                best = None
                for key0 in seeds:
                    key = list(key0)
                    cur = _flagaware(_xor(data, bytes(key)))
                    for _ in range(ascent_rounds):
                        improved = False
                        for c in range(L):
                            for k in trial_cols[c]:
                                if k == key[c]:
                                    continue
                                trial = key[:]
                                trial[c] = k
                                sc = _flagaware(_xor(data, bytes(trial)))
                                if sc > cur + 1e-9:
                                    cur, key, improved = sc, trial, True
                        if not improved:
                            break
                    if best is None or cur > best[0]:
                        best = (cur, key[:])
                out = _xor(data, bytes(best[1]))
                cands.append((best[0] - mdl(L),
                              _primitive_key(bytes(best[1])), out))
    if cands:
        cands.sort(key=lambda r: r[0], reverse=True)
        seen, picked = set(), []
        for adj, k, o in cands:
            if o not in seen:
                seen.add(o)
                picked.append((adj, k, o))
        for i, (adj, k, o) in enumerate(picked[:3]):
            params = {"key_hex": k.hex()}
            if i == 0:
                margin = adj - picked[1][0] if len(picked) > 1 else .5
                params["_statistical"] = True
                yield o, "repeating-key XOR", params, _margin_conf(margin)
            else:
                yield o, "repeating-key XOR", params, _rank_score(o)
        return
    sizes = range(2, min(41, len(data) // 3))
    distances = []
    for size in sizes:
        blocks = [data[i:i + size] for i in range(0, min(len(data), size * 5), size)]
        pairs = [_hamming(blocks[i], blocks[i + 1]) / size for i in range(len(blocks) - 1)]
        if pairs:
            distances.append((sum(pairs) / len(pairs), size))
    likely = [s for _, s in sorted(distances)[:16]]
    ranked = []
    for size in likely:
        key = _primitive_key(_repeat_xor_key(data, size))
        out = _xor(data, key)
        ranked.append((assess(out)[0], key, out))
    for score, key, out in sorted(ranked, reverse=True)[:3]:
        yield out, "repeating-key XOR", {"key_hex": key.hex()}, score


@solver("known-plaintext-XOR", lambda fp: .99 if fp["length"] else 0)
def solve_xor_crib(data, ctx):
    if not ctx.known_plaintext or len(data) > 1_000_000 or ctx.depth > 0:
        return
    crib = ctx.known_plaintext.encode()
    for off in range(len(data) - len(crib) + 1):
        key = bytes(data[off + i] ^ crib[i] for i in range(len(crib)))
        # Treat crib length as a repeating key only when its inferred periods agree.
        for size in range(1, min(len(key), 64) + 1):
            if all(key[i] == key[i % size] for i in range(len(key))):
                out = _xor(data, key[:size])
                if crib in out:
                    yield out, "known-plaintext XOR", {"key_hex": key[:size].hex()}, 1.0
                    return


_HEX_BLOB_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_SAMPLE_SENT_RE = re.compile(r"[\"']([A-Za-z][A-Za-z0-9 .,'!?\-:;]{15,})[\"']")


def _sample_ks_prior(fp):
    if fp.get("charset") != "ascii-text":
        return 0.0
    t = fp.get("_text", "")
    if len(t) < 200:
        return 0.0
    if not _SAMPLE_SENT_RE.search(t):
        return 0.0
    if len(_HEX_BLOB_RE.findall(t)) < 2:
        return 0.0
    return 0.5


@solver("sample-keystream-xor", _sample_ks_prior)
def solve_sample_keystream_xor(data, ctx):
    """Recover a repeating-key XOR keystream from a source that provides a
    known sample plaintext together with its ciphertext (hex) and the target
    ciphertext (hex) under the same key — e.g. xorly's
    `Plaintext: "..." / Ciphertext: <hex> / Flag: <hex>` pattern."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    sents = _SAMPLE_SENT_RE.findall(text)
    blobs = [b for b in _HEX_BLOB_RE.findall(text)]
    if not sents or len(blobs) < 2:
        return
    pt_bytes = max(sents, key=len).encode("utf-8")

    def _tb(h):
        try:
            return bytes.fromhex(h)
        except Exception:
            return None

    ct_cand, others = None, []
    for h in blobs:
        b = _tb(h)
        if b is None:
            continue
        if len(b) == len(pt_bytes):
            ct_cand = b
        else:
            others.append(b)
    if ct_cand is None:
        # fallback: assume the longest hex blob is the sample ciphertext
        ct_cand = max(others, key=len)
        others = [b for b in others if b is not ct_cand]
    if not ct_cand or not others:
        return
    ks = bytes(a ^ b for a, b in zip(pt_bytes, ct_cand))
    if not ks:
        return
    results = []
    for size in range(1, min(len(ks), 64) + 1):
        key = ks[:size]
        for target in others:
            out = _xor(target, key)
            sc = _rank_score(out)
            results.append((sc, size, key, out))
    if not results:
        return
    seen, yielded = set(), 0
    for sc, size, key, out in sorted(results, reverse=True):
        if out in seen:
            continue
        seen.add(out)
        claim = max(0.7, min(0.985, sc))
        yield out, "sample-keystream xor", {"key_hex": key.hex(), "period": size}, claim
        yielded += 1
        if yielded >= 3:
            break


@solver("many-time-pad", lambda fp: .25 if fp["length"] >= 16 else 0)
def solve_many_time_pad(data, ctx):
    # Accept newline-separated hex ciphertexts, one per line.
    if ctx.depth > 0:
        return
    lines = data.splitlines()
    if len(lines) < 2:
        return
    try:
        ciphers = [bytes.fromhex(line.decode().strip()) for line in lines if line.strip()]
    except (ValueError, UnicodeError):
        return
    if len(ciphers) < 2 or not ciphers or max(map(len, ciphers)) > 10_000:
        return
    ctx.findings.append("Multiple ciphertexts supplied; possible reused stream-cipher nonce.")
    cribs = [ctx.known_plaintext.encode()] if ctx.known_plaintext else []
    cribs.extend([b" the ", b" and ", b" flag{", b" the", b" of "])
    candidates = []
    for a, b in itertools.combinations(ciphers, 2):
        for crib in cribs:
            for off in range(max(1, min(len(a), len(b)) - len(crib) + 1)):
                if off + len(crib) > min(len(a), len(b)):
                    continue
                key = bytes(a[off + i] ^ crib[i] for i in range(len(crib)))
                plain = bytes(b[off + i] ^ key[i] for i in range(len(crib)))
                candidates.append((plain, off))
    for plain, off in candidates[:3]:
        yield from _emit(ctx, plain, "many-time-pad crib drag", {"offset": off})


def _b64url(part):
    return base64.urlsafe_b64decode(part + b"=" * ((-len(part)) % 4))


@solver("JWT", lambda fp: _prior(fp, "jwt"))
def solve_jwt(data, ctx):
    try:
        head, body, sig = data.strip().split(b".")
        header = json.loads(_b64url(head))
        payload = json.loads(_b64url(body))
        out = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if header.get("alg", "").lower() == "none" and not sig:
            ctx.findings.append("JWT uses alg=none (unsigned token).")
        yield from _emit(ctx, out, "JWT payload decode", {"alg": header.get("alg", "?")})
        if header.get("alg") == "HS256" and ctx.wordlist:
            signing = head + b"." + body
            for secret in ctx.wordlist:
                digest = hmac.new(secret.strip(), signing, hashlib.sha256).digest()
                if hmac.compare_digest(digest, _b64url(sig)):
                    ctx.findings.append("JWT HS256 secret recovered from wordlist.")
                    yield from _emit(ctx, out, "JWT HS256 cracked", {"secret": secret.decode("utf-8", "replace")})
                    break
    except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
        return


def _md4(data: bytes) -> bytes:
    """Small pure-Python MD4 fallback used for NTLM wordlist checks."""
    msg = bytearray(data)
    bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bitlen.to_bytes(8, "little")
    mask = 0xffffffff
    def rol(x, n):
        x &= mask
        return ((x << n) | (x >> (32 - n))) & mask
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    for block in range(0, len(msg), 64):
        X = [int.from_bytes(msg[block + i:block + i + 4], "little") for i in range(0, 64, 4)]
        a, b, c, d = h
        for i in range(16):
            k = i; s = (3, 7, 11, 19)[i % 4]
            f = (b & c) | (~b & d)
            a, b, c, d = d, rol(a + f + X[k], s), b, c
        for i in range(16):
            k = (i % 4) * 4 + i // 4; s = (3, 5, 9, 13)[i % 4]
            g = (b & c) | (b & d) | (c & d)
            a, b, c, d = d, rol(a + g + X[k] + 0x5a827999, s), b, c
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in range(16):
            k = order[i]; s = (3, 9, 11, 15)[i % 4]
            hh = b ^ c ^ d
            a, b, c, d = d, rol(a + hh + X[k] + 0x6ed9eba1, s), b, c
        h = [(x + y) & mask for x, y in zip(h, (a, b, c, d))]
    return b"".join(x.to_bytes(4, "little") for x in h)


@solver("hash-identification", lambda fp: .95 if fp["hashes"] else 0)
def solve_hash(data, ctx):
    if ctx.depth > 0:
        return
    if not data.strip():
        return
    kind = fingerprint_hash(data.strip())
    if not kind:
        return
    ctx.findings.append(f"Hash fingerprint: {kind}.")
    if not ctx.wordlist:
        return
    target_bytes = data.strip()
    target = target_bytes.decode("ascii", "ignore").lower()
    if kind == "bcrypt" and _bcrypt is None:
        ctx.findings.append("bcrypt identified; wordlist cracking needs the optional bcrypt module.")
        return
    cost_match = re.match(r"^\$2[aby]\$(\d\d)\$", target)
    bcrypt_cost = int(cost_match.group(1)) if cost_match else 99
    for word in ctx.wordlist:
        if ctx.expired():
            return
        raw = word.rstrip(b"\r\n")
        if kind == "bcrypt":
            if bcrypt_cost > 14:
                ctx.findings.append("bcrypt cost is too high for a bounded wordlist attempt.")
                return
            try:
                # bcrypt hashes are case-sensitive; use the original bytes,
                # not the lowercased copy used for hex digest comparison.
                if _bcrypt.checkpw(raw, target_bytes):
                    yield from _emit(ctx, raw, "cracked bcrypt", {"word": raw.decode("utf-8", "replace")})
                    return
            except (ValueError, TypeError):
                return
            continue
        checks = {
            "MD5": hashlib.md5(raw).hexdigest(),
            "SHA-1": hashlib.sha1(raw).hexdigest(),
            "SHA-256": hashlib.sha256(raw).hexdigest(),
            "NTLM": _md4(raw.decode("utf-8", "replace").encode("utf-16le")).hex(),
        }
        if target in checks.values():
            yield from _emit(ctx, raw, f"cracked {kind}", {"word": raw.decode("utf-8", "replace")})
            return


def fingerprint_hash(data):
    if re.fullmatch(rb"[0-9a-fA-F]{32}", data):
        return "MD5/NTLM"
    if re.fullmatch(rb"[0-9a-fA-F]{40}", data):
        return "SHA-1"
    if re.fullmatch(rb"[0-9a-fA-F]{64}", data):
        return "SHA-256"
    if re.fullmatch(rb"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", data):
        return "bcrypt"
    return ""


def _parse_int(value):
    if isinstance(value, int):
        return value
    value = str(value).strip().replace("_", "").replace(",", "")
    return int(value, 0) if value.lower().startswith("0x") else int(value, 10)


def _rsa_values(data, ctx):
    values = dict(ctx.rsa_params or {})
    try:
        obj = json.loads(data.decode("utf-8"))
        if isinstance(obj, dict):
            for k, v in obj.items():
                values.setdefault(k.lower(), v)
    except (UnicodeError, json.JSONDecodeError):
        pass
    if ctx.rsa_params or sum(c in (9, 10, 13) or 32 <= c < 127 for c in data[:100_000]) / max(1, min(len(data), 100_000)) > .8:
        try:
            text = data.decode("ascii", "ignore")
            for key, value in re.findall(
                r"\b(n\d*|modulus\d*|e\d*|exponent\d*|c\d*|ciphertext\d*|cyphertext\d*|cypher\d*|cipher\d*|ct\d*|enc\d*|encrypted\d*|message\d*|msg\d*|p\d*|q\d*|d\d*|priv\d*|private_exponent\d*|p_high|p_hi|phigh)\s*[:=]?\s*(0x[0-9a-f]+|\d+)",
                text, re.I,
            ):
                values.setdefault(key.lower(), value)
        except Exception:
            pass
    normalized = {}
    aliases = {
        "n": ("n", "modulus"), "e": ("e", "exponent"),
        "c": ("c", "ciphertext", "cyphertext", "cypher", "cipher", "ct", "enc", "encrypted", "message", "msg"),
        "d": ("d", "priv", "private", "private_exponent", "d_"),
    }
    for target, keys in aliases.items():
        for key in keys:
            if key in values:
                try:
                    normalized[target] = _parse_int(values[key])
                    break
                except (ValueError, TypeError):
                    pass
    normalized.update({k: v for k, v in values.items() if re.fullmatch(r"(?:n|e|c|p|q|d)\d*", k)})
    # Partial factorization hint: high bits of a prime factor (Coppersmith).
    if "p_high" in values or "p_hi" in values:
        try:
            normalized["p_high"] = _parse_int(
                values.get("p_high", values.get("p_hi")))
        except (ValueError, TypeError):
            pass
    for key, value in list(normalized.items()):
        if isinstance(value, str):
            try:
                normalized[key] = _parse_int(value)
            except ValueError:
                normalized.pop(key, None)
    # Unlabeled fallback: exactly three large integers in the file, no
    # n/e/c labels found, in "n e c" order. Guarded to avoid hijacking
    # other 3-number formats (e.g. DLP/LGG triples): n > c, e >= 2.
    # Only used when labels did NOT already provide n or c (otherwise a
    # labeled "n,c,d" triple would be misread as "n,e,c").
    if not (normalized.get("n") or normalized.get("c")):
        try:
            text = data.decode("ascii", "ignore")
            nums = [int(x) for x in re.findall(r"\b\d+\b", text)]
            if len(nums) == 3 and nums[0] > nums[2] and nums[1] >= 2 and nums[2] > 0:
                normalized.setdefault("n", nums[0])
                normalized.setdefault("e", nums[1])
                normalized.setdefault("c", nums[2])
            elif len(nums) == 4 and nums[2] >= 2 and nums[0] * nums[1] > nums[3] > 0:
                # unlabeled "p q e c" (any order p/q is fine)
                normalized.setdefault("p", nums[0])
                normalized.setdefault("q", nums[1])
                normalized.setdefault("e", nums[2])
                normalized.setdefault("c", nums[3])
        except Exception:
            pass
    return normalized


def _integer_root(n, e):
    if n < 0 or e < 1:
        return None
    if gmpy2 is not None:
        root, exact = gmpy2.iroot(n, e)
        return int(root) if exact else None
    lo, hi = 0, 1 << ((n.bit_length() + e - 1) // e + 1)
    while lo <= hi:
        mid = (lo + hi) // 2
        power = mid ** e
        if power == n:
            return mid
        if power < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return None


def _inv(a, n):
    if _crypto_inverse is not None:
        try:
            return int(_crypto_inverse(a, n))
        except ValueError:
            return None
    try:
        return pow(a, -1, n)
    except ValueError:
        return None


def _tonelli_shanks(a, p):
    """Square root of a mod p (prime), or None if a is a non-residue."""
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c = s, pow(z, q, p)
    t, r = pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2i = 0, t
        while t2i != 1:
            t2i = t2i * t2i % p
            i += 1
            if i >= m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        cn = b * b % p  # c_new; t must be updated with c_new, not the old c
        m, c = i, cn
        t = t * cn % p
        r = r * b % p
    return r


def _rabin_sqrt(c, p, q, n):
    """All four square roots of c modulo n=pq (Rabin), or []."""
    rp = _tonelli_shanks(c, p)
    rq = _tonelli_shanks(c, q)
    if rp is None or rq is None:
        return []
    out = set()
    for sp in (rp, (-rp) % p):
        for sq in (rq, (-rq) % q):
            m = _crt([sp, sq], [p, q])
            if m is not None:
                out.add(m % n)
    return sorted(out)


def _int_plain(n):
    if n < 0:
        return b""
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def _maybe_reverse_flag(raw):
    """Some challenges store the plaintext *reversed* before RSA, so the
    decrypted bytes come back with the flag braces swapped (`}...{` instead of
    `{...}`). If `raw` shows that swapped-brace signature, return the reversed
    bytes (which recover the correct flag shell); otherwise return None."""
    if not raw:
        return None
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if "{" not in s or "}" not in s or len(s) > 512:
        return None
    # Correct orientation has '{' before '}'. If they are swapped, reverse.
    if s.find("}") < s.rfind("{"):
        r = raw[::-1]
        try:
            rs = r.decode("ascii")
        except UnicodeDecodeError:
            return r
        if rs.find("{") < rs.rfind("}"):
            return r
    return None


def _emit_rsa(ctx, m, method, params=None):
    """Yields the direct decrypted plaintext, plus (when present) its reversed
    form if the message was stored reversed (swapped flag braces)."""
    params = params or {}
    plain = _int_plain(m)
    yield from _emit(ctx, plain, method, params)
    rev = _maybe_reverse_flag(plain)
    if rev is not None and rev != plain:
        p2 = dict(params)
        p2["reversed"] = True
        yield from _emit(ctx, rev, method + " (reversed)", p2)


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _pollard_rho(n, ctx):
    if n % 2 == 0:
        return 2
    rng = random.Random(0xC7F)
    for _ in range(12):
        x = rng.randrange(2, n - 1)
        y, c, d = x, rng.randrange(1, n - 1), 1
        for _ in range(12_000):
            if ctx.expired():
                return None
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if d == n:
                break
            if d > 1:
                return d
    return None


def _factordb_lookup(n):
    """External last-resort factorization via factorDB (public DB). Returns
    (p, q) when the modulus is indexed, else None. Silently returns None on any
    failure (no network, timeout, malformed reply). Disable with the env var
    AUTOCRYPT_NO_FACTORDBA=1."""
    if n <= 1 or n.bit_length() < 160:
        return None
    if os.environ.get("AUTOCRYPT_NO_FACTORDBA"):
        return None
    try:
        import urllib.request
        import socket as _socket
        req = urllib.request.Request(
            "https://factordb.com/api?query=%d" % n,
            headers={"User-Agent": "autocrypt/1.0"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.load(resp)
        fac = data.get("factors") if isinstance(data, dict) else None
        if not isinstance(fac, list):
            return None
        ps = []
        for item in fac:
            if not isinstance(item, (list, tuple)) or not item:
                continue
            try:
                fp = int(item[0])
            except (TypeError, ValueError):
                continue
            mult = 1
            if len(item) >= 2:
                try:
                    mult = int(item[1])
                except (TypeError, ValueError):
                    mult = 1
            if fp > 1 and mult >= 1:
                ps.extend([fp] * mult)
        if len(ps) < 2:
            return None
        if math.prod(ps) != n:
            return None
        p = ps[0]
        q = math.prod(ps[1:]) if len(ps) > 2 else ps[1]
        if p > 1 and q > 1 and p * q == n:
            return p, q
    except Exception:
        return None
    return None


def _factor(n, ctx):
    if n % 2 == 0:
        return 2, n // 2
    # Bounded small-prime trial division.
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n % p == 0:
            return p, n // p
    for p in range(53, 20_001, 2):
        if ctx.expired():
            return None
        if n % p == 0:
            return p, n // p
    # Fermat finds RSA moduli made from close primes.
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(250_000):
        if ctx.expired():
            return None
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
    p = _pollard_rho(n, ctx)
    if p:
        return p, n // p
    # Last resort: the full factor_all pipeline (pm1/pp1/rho/batched ECM).
    try:
        from autocrypt.solvers_more import factor_all
        fa = factor_all(n, ctx)
        if fa and len(fa) == 2:
            a, b = list(fa)
            return a, b
        if fa:
            a = next(iter(fa))
            return a, n // a
    except Exception:
        pass
    # Balanced semiprimes beyond ~192-bit defeat every built-in method. As a
    # final fallback (optionally disabled via AUTOCRYPT_NO_FACTORDBA=1), ask
    # factorDB (public factorization database) — many CTF moduli are indexed.
    fb = _factordb_lookup(n)
    if fb:
        return fb
    return None


def _wiener(n, e):
    a, b = e, n
    cf = []
    while b:
        q, a, b = a // b, b, a % b
        cf.append(q)
    p0, p1, q0, q1 = 0, 1, 1, 0
    for x in cf:
        p = x * p1 + p0
        q = x * q1 + q0
        p0, p1, q0, q1 = p1, p, q1, q
        if q == 0 or p == 0:
            continue
        k, d = p, q
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            root = math.isqrt(disc)
            if root * root == disc and (s + root) % 2 == 0:
                return d
    return None


# p-size hypotheses (exponent beta with p ~ n^beta) tried by
# _recover_p_partial, balanced (0.5) first. The lower/upper coverage lets an
# unbalanced prime factor (p not ~sqrt(n)) still be recovered: the unknown
# low-bit count is m = floor(beta*log2 n) - bitlen(p_high).
_P_BETA_HYPOTHESES = (0.50, 0.47, 0.53, 0.44, 0.56, 0.41, 0.59, 0.38,
                       0.62, 0.35, 0.65, 0.60, 0.40, 0.67, 0.33)
# per-beta offset neighbourhood around base = round(beta*nbits) - hp
_P_BETA_OFFSETS = (0, 1, -1)
_P_MAX_TRIES = 30
_P_SWEEP_MM = 2  # dimension used for cheap sweep tries (fast; mm=3 if needed)


def _recover_p_partial(n, p_high, ctx):
    """Recover a prime factor p of n when the high bits of p are known.

    p = (p_high << m) + x with 0 <= x < 2^m. Coppersmith's method (see
    lattice.py) recovers x; the unknown low-bit count m is inferred from the
    size of p (assumed p ~ n^beta), trying several beta hypotheses (balanced
    first, then unbalanced), each with a few neighbouring m values.
    """
    if n <= 1 or not p_high or p_high >= n:
        return None
    try:
        import autocrypt.lattice as lattice
    except Exception:
        return None
    nbits = n.bit_length()
    hp = p_high.bit_length()
    tried = set()

    def try_m(m, escalate=True, mm=_P_SWEEP_MM, max_escalate=None):
        if m in tried:
            return None
        tried.add(m)
        if m < 1 or m >= nbits:
            return None
        if ctx.expired():
            return None
        p = lattice.coppersmith_partial_p(
            n, p_high, m, mm=mm, tt=1, check=lambda: not ctx.expired(),
            escalate=escalate, max_escalate=max_escalate)
        if p is not None and 1 < p < n and n % p == 0:
            return p
        return None

    if nbits > 80:
        # Interleave upper/lower imbalance hypotheses (|beta-0.5| asc), so a
        # moderately unbalanced factor is reached early; balanced comes first.
        by_imb = sorted(set(_P_BETA_HYPOTHESES), key=lambda b: abs(b - 0.5))
        betas = [by_imb[0]]
        upper = [b for b in by_imb[1:] if b > 0.5]
        lower = [b for b in by_imb[1:] if b < 0.5]
        for i in range(max(len(upper), len(lower))):
            if i < len(upper):
                betas.append(upper[i])
            if i < len(lower):
                betas.append(lower[i])

        # Order all hypotheses (balanced first, interleaved upper/lower) and
        # try them cheaply at mm=2; only then escalate the closest (balanced-
        # first) candidates. Cheap-first keeps unbalanced inputs fast, and the
        # small escalated fallback handles harder balanced leak sizes. The
        # deadline check inside lll bounds the escalation cost.
        order = []
        for b in betas:
            base = max(1, int(round(b * nbits)) - hp)
            for off in _P_BETA_OFFSETS:
                m = base + off
                if m not in tried and len(order) < _P_MAX_TRIES:
                    order.append(m)
                    tried.add(m)
        tried.clear()
        for m in order:
            p = try_m(m, escalate=False)
            if p:
                return p
        if not ctx.expired():
            tried.clear()
            for m in order[:5]:
                p = try_m(m, escalate=True)
                if p:
                    return p
        return None
    # small n: try the whole plausible range cheaply
    for m in range(max(1, hp // 8), nbits):
        p = try_m(m, escalate=False)
        if p:
            return p
    return None


def _crt(residues, moduli):
    product = math.prod(moduli)
    total = 0
    for r, n in zip(residues, moduli):
        part = product // n
        inv = _inv(part, n)
        if inv is None:
            return None
        total += r * part * inv
    return total % product


@solver("RSA", lambda fp: .99 if fp["length"] else 0)
def solve_rsa(data, ctx):
    if ctx.depth > 0:
        return
    vals = _rsa_values(data, ctx)
    n, e, c = vals.get("n"), vals.get("e"), vals.get("c")
    if not n and vals.get("p") and vals.get("q"):
        try:
            n = int(vals["p"]) * int(vals["q"])
            vals["n"] = n
        except (TypeError, ValueError):
            pass
    # Tiny RSA-like assignments frequently appear by chance in arbitrary bytes.
    # Only the very smallest values are filtered (genuine tiny-RSA textbook
    # challenges still pass); the params/UI path is never blocked by this.
    if not ctx.rsa_params and n is not None and n < 32:
        return
    # Block RSA: the ciphertext is a *list* of independently encrypted values,
    # all sharing the same n/e (e.g. one value per plaintext byte/block). The
    # text contains many numbers, each < n; factor once and decrypt every block.
    if n and n > 1 and (e or vals.get("d")):
        try:
            _text = data.decode("ascii", "ignore")
        except Exception:
            _text = ""
        if _text:
            try:
                _nums = [int(x) for x in re.findall(r"\b\d+\b", _text)]
            except Exception:
                _nums = []
            # Reserve the known parameter values so they are never misread as
            # ciphertext blocks (e.g. when p/q/d are supplied alongside n/e, or
            # when source hints provide p1..pN / q1..qN primes).
            _reserved = {v for v in (n, e, vals.get("c"), vals.get("p"),
                                     vals.get("q"), vals.get("d"))
                         if isinstance(v, int)}
            for _k, _v in vals.items():
                if re.fullmatch(r"(?:p|q)\d+", _k) and isinstance(_v, int):
                    _reserved.add(_v)
            _blocks = [x for x in _nums if x not in _reserved]
            if len(_blocks) >= 3 and all(0 < x < n for x in _blocks):
                _d_b = vals.get("d")
                _p_b, _q_b = vals.get("p"), vals.get("q")
                try:
                    if _d_b is None and _p_b and _q_b and int(_p_b) * int(_q_b) == n:
                        _d_b = _inv(e, (int(_p_b) - 1) * (int(_q_b) - 1))
                    elif _d_b is None:
                        _f = _factor(n, ctx)
                        if _f:
                            _pp, _qq = _f
                            _d_b = _inv(e, (_pp - 1) * (_qq - 1))
                    if _d_b is not None and (_d_b := int(_d_b)) > 0:
                        _ms = [pow(x, _d_b, n) for x in _blocks]
                        # When e is available, verify every block (m^e == c) so a
                        # wrong supplied d never yields a confident garbage result.
                        if e and e > 1 and any(
                                pow(m, e, n) != blk
                                for m, blk in zip(_ms, _blocks)):
                            _ms = []
                        _out = b"".join(_int_plain(m) for m in _ms)
                        if _out:
                            yield from _emit(
                                ctx, _out, "RSA block",
                                {"n": n, "e": e, "blocks": len(_blocks),
                                 "d": _d_b})
                            return
                except (TypeError, ValueError):
                    pass
    # Pure private-exponent decode: a supplied d is mathematically sufficient on
    # its own (m = c^d mod n); e is only needed to *verify* the result. This
    # must work even when no public exponent was provided. A wrong d is rejected
    # (or just not verified to be correct) and never swallows the crack paths.
    _d_given = vals.get("d")
    if c is not None and n and n > 1 and _d_given is not None:
        try:
            _dd = int(_d_given)
        except (TypeError, ValueError):
            _dd = -1
        if _dd > 0 and 0 <= c < n:
            _m = pow(c, _dd, n)
            _ok = True
            if e and e > 1:
                _ok = pow(_m, e, n) == c
            if _ok:
                yield from _emit_rsa(
                    ctx, _m, "RSA known-d",
                    {"n": n, "e": e, "c": c, "d": _dd, "m": _m})
                return
    if n and e and c is not None and n > 1 and e > 0:
        # e=1 is the identity encryption: c == m mod n, so the plaintext is c
        # itself (when c < n). Decisive; report it and stop.
        if e == 1 and c < n:
            yield from _emit(ctx, _int_plain(c), "RSA e=1",
                             {"n": n, "e": e, "c": c, "m": c})
            return
        # Low exponent with reduction: when m^e >= n, c = m^e mod n, so m^e =
        # c + i*n for some small i. Scan i BEFORE any factoring (cheap and
        # decisive). e <= 5 keeps the scan bounded; e=3 is the classic picoCTF
        # Mini-RSA shape. The exact m**e == c gate prevents false positives.
        if 2 <= e <= 5 and c < n:
            _cap = 250_000 if e == 3 else (1 << 12)
            for i in range(_cap):
                if ctx.expired():
                    break
                val = c + i * n
                m = _integer_root(val, e)
                if m is not None and m ** e == val:
                    yield from _emit(ctx, _int_plain(m), "RSA small-e overflow cube-root",
                                     {"n": n, "e": e, "c": c, "i": i, "m": m})
                    break
        # Multi-prime RSA: source-hint primes p1..pN / q1..qN whose product
        # equals the modulus. Checked BEFORE factoring so a large composite
        # never costs a slice, and so the first (highest-prior) RSA solver
        # returns instantly instead of starving the remaining search.
        given_primes = sorted({val for k, val in vals.items()
                              if re.fullmatch(r"(?:p|q)\d+", k)})
        if len(given_primes) >= 2 and math.prod(given_primes) == n:
            _phi = 1
            for pp in given_primes:
                _phi *= pp - 1
            _d = _inv(e, _phi)
            if _d is not None:
                _m = pow(c, _d, n)
                yield from _emit_rsa(
                    ctx, _m, "RSA factored",
                    {"n": n, "e": e, "primes": given_primes,
                     "d": _d, "m": _m})
                return
        # p and q are given: decrypt directly via phi(n) — no factoring needed.
        if vals.get("p") and vals.get("q"):
            try:
                _pp, _qq = int(vals["p"]), int(vals["q"])
                if _pp * _qq == n:
                    _phi = (_pp - 1) * (_qq - 1)
                    _d = _inv(e, _phi)
                    if _d is not None:
                        _m = pow(c, _d, n)
                        yield from _emit_rsa(
                            ctx, _m, "RSA factored",
                            {"n": n, "e": e, "p": _pp,
                             "q": _qq, "d": _d, "m": _m})
                        return
            except (TypeError, ValueError):
                pass
        # (known-d decryption is handled above, independent of the e-gate.)
        # Small exponent: recover via an exact integer root. Earlier this only
        # ran when c < n, but some challenges publish an *unreduced* m^e (a
        # perfect e-th power) that exceeds n (e.g. picoCTF-style "e should be
        # larger"). The exact check m**e == c gates false positives on properly
        # reduced RSA, so it is safe to attempt whenever e is small.
        if c >= 0 and e <= 17:
            m = _integer_root(c, e)
            if m is not None and m ** e == c:
                yield from _emit(ctx, _int_plain(m), "RSA small-e exact root",
                                 {"n": n, "e": e, "c": c, "m": m})
        if c < n and e > 1:
            # Wiener attack for an unusually small private exponent.
            d = _wiener(n, e)
            if d:
                m = pow(c, d, n)
                yield from _emit(ctx, _int_plain(m), "RSA Wiener attack",
                                 {"n": n, "e": e, "d": d, "m": m})
            # Partial factorization: the high bits of p are known (Coppersmith).
            ph = vals.get("p_high")
            if ph and not vals.get("p") and not vals.get("q"):
                pp = _recover_p_partial(n, ph, ctx)
                if pp:
                    qq = n // pp
                    phi = (pp - 1) * (qq - 1)
                    dd = _inv(e, phi)
                    if dd is not None:
                        mm = pow(c, dd, n)
                        yield from _emit_rsa(
                            ctx, mm, "RSA partial-p (Coppersmith)",
                            {"n": n, "e": e, "p": pp, "q": qq,
                             "d": dd, "m": mm})
                        return
            factors = _factor(n, ctx)
            if factors:
                p, q = factors
                if e == 2:
                    # Rabin: e=2 is not invertible mod phi, so decrypt by
                    # taking square roots modulo p and q and combining.
                    for mm in _rabin_sqrt(c, p, q, n):
                        yield from _emit(ctx, _int_plain(mm), "RSA Rabin sqrt",
                                         {"n": n, "e": e, "m": mm})
                else:
                    phi = (p - 1) * (q - 1)
                    d = _inv(e, phi)
                    if d is not None:
                        m = pow(c, d, n)
                        yield from _emit_rsa(
                            ctx, m, "RSA factored",
                            {"n": n, "e": e, "p": p, "q": q, "d": d, "m": m})
    # Small exponent WITHOUT a published modulus: some challenges publish only
    # `e` and `c` where c is an *unreduced* m^e (a perfect e-th power), e.g.
    # CSAW Teen RSA (e=3, no n printed). No modulus is needed for the exact
    # root; the m**e == c check gates false positives on proper ciphertexts.
    if not n and e is not None and c is not None and c >= 0 and e <= 17:
        m = _integer_root(c, e)
        if m is not None and m ** e == c:
            yield from _emit(ctx, _int_plain(m), "RSA small-e exact root (no modulus)",
                             {"e": e, "c": c, "m": m})
    # Common-modulus case: same n, different exponents and ciphertexts.
    e1, c1, e2, c2 = (vals.get(k) for k in ("e1", "c1", "e2", "c2"))
    if n and all(x is not None for x in (e1, c1, e2, c2)):
        g, a, b = _egcd(e1, e2)
        x = pow(c1, a, n) if a >= 0 else pow(_inv(c1, n) or 0, -a, n)
        y = pow(c2, b, n) if b >= 0 else pow(_inv(c2, n) or 0, -b, n)
        m = (x * y) % n
        if g == 1:
            yield from _emit(ctx, _int_plain(m), "RSA common-modulus",
                             {"n": n, "e1": e1, "e2": e2, "m": m})
        else:
            root = _integer_root(m, g)
            if root is not None:
                yield from _emit(ctx, _int_plain(root), "RSA common-modulus root",
                                 {"n": n, "g": g, "m": root})
    # Håstad broadcast: n_i / c_i triples. Each triple may carry its own
    # exponent (e1/e2/e3), or a single shared exponent `e` may apply to all
    # moduli (the common real-world shape: same public exponent e across
    # recipients, e.g. c10's broadcast).
    triples = []
    shared_e = vals.get("e")
    i = 1
    while vals.get(f"n{i}") is not None and vals.get(f"c{i}") is not None:
        ei = vals.get(f"e{i}")
        if ei is None:
            ei = shared_e
        if ei is None:
            break
        triples.append((vals[f"n{i}"], ei, vals[f"c{i}"]))
        i += 1
    if len(triples) >= 2 and len({x[1] for x in triples}) == 1:
        exp = triples[0][1]
        if len(triples) >= exp:
            combined = _crt([x[2] for x in triples[:exp]], [x[0] for x in triples[:exp]])
            m = _integer_root(combined, exp) if combined is not None else None
            if m is not None:
                yield from _emit(ctx, _int_plain(m), "RSA Hastad broadcast",
                                 {"e": exp, "m": m, "moduli": [x[0] for x in triples[:exp]]})


# More encodings/ciphers and image/file steganography, kept in their own
# modules; importing here registers them into the same REGISTRY.
import autocrypt.solvers_extra  # noqa: E402,F401
import autocrypt.stego  # noqa: E402,F401
import autocrypt.solvers_mega  # noqa: E402,F401
import autocrypt.solvers_more  # noqa: E402,F401
import autocrypt.solvers_gaps  # noqa: E402,F401
import autocrypt.solvers_plus  # noqa: E402,F401
import autocrypt.solvers_pack3  # noqa: E402,F401
import autocrypt.solvers_pack5  # noqa: E402,F401
import autocrypt.solvers_pack6  # noqa: E402,F401
import autocrypt.solvers_pack7  # noqa: E402,F401


# ------------------------------------------------ G2: linear recurrence + derived key
import sys as _sys
try:
    _sys.set_int_max_str_digits(30000)
except Exception:
    pass

def _g2_safe_eval(node, consts):
    """Safe static evaluation of integer expressions (int(...), **, named consts)."""
    import ast
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, float) and node.value.is_integer():
        return int(node.value)
    if isinstance(node, ast.Name):
        v = consts.get(node.id)
        return v if isinstance(v, int) else None
    if isinstance(node, ast.BinOp):
        a = _g2_safe_eval(node.left, consts)
        b = _g2_safe_eval(node.right, consts)
        if a is None or b is None:
            return None
        if isinstance(node.op, ast.Add):
            return a + b
        if isinstance(node.op, ast.Sub):
            return a - b
        if isinstance(node.op, ast.Mult):
            return a * b
        if isinstance(node.op, ast.Pow):
            return a ** b
        if isinstance(node.op, ast.FloorDiv):
            return a // b
        if isinstance(node.op, ast.Mod):
            return a % b
        return None
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("int", "abs"):
        if node.args and len(node.args) <= 2:
            v = _g2_safe_eval(node.args[0], consts)
            return v if v is not None else None
    return None


def _g2_offset_of(node, argname, consts):
    """i, i-4, i+2, or numeric offset."""
    import ast
    if isinstance(node, ast.Name) and node.id == argname:
        return 0
    if isinstance(node, ast.BinOp):
        left, op, right = node.left, node.op, node.right
        if isinstance(left, ast.Name) and left.id == argname:
            c = _g2_safe_eval(right, consts)
            off = c if isinstance(op, ast.Sub) else -c if isinstance(op, ast.Add) else None
            # Reject negative offsets (invalid index deltas).
            if off is not None and off >= 0:
                return off
        if isinstance(right, ast.Name) and right.id == argname and isinstance(op, ast.Sub):
            c = _g2_safe_eval(left, consts)
            if c is not None and c >= 0:
                return c
    return _g2_safe_eval(node, consts)


def _g2_extract_linear(node, fname, base, argname=None):
    """Recursively parse an expression tree into (coeffs {offset:int}, constant)."""
    import ast
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") == fname and node.args:
        off = _g2_offset_of(node.args[0], argname, base) if argname else _g2_safe_eval(node.args[0], base)
        if off is not None:
            return {off: 1}, 0
    if isinstance(node, ast.BinOp):
        a_raw = _g2_extract_linear(node.left, fname, base, argname)
        if a_raw is None:
            return None
        a, ca = a_raw
        b_raw = _g2_extract_linear(node.right, fname, base, argname)
        if b_raw is None:
            return None
        b, cb = b_raw
        if isinstance(node.op, ast.Add):
            c = {}
            for k, v in list(a.items()) + list(b.items()):
                c[k] = c.get(k, 0) + v
            return c, ca + cb
        if isinstance(node.op, ast.Sub):
            c = dict(a)
            for k, v in b.items():
                c[k] = c.get(k, 0) - v
            return c, ca - cb
        if isinstance(node.op, ast.Mult):
            if not a and isinstance(b, dict) and isinstance(ca, int):
                return {k: v * ca for k, v in b.items()}, 0
            if not b and isinstance(a, dict) and isinstance(cb, int):
                return {k: v * cb for k, v in a.items()}, 0
            return None
        return None
    const = _g2_safe_eval(node, base)
    if const is not None:
        return {}, const
    return None


def _g2_analyze(src):
    """Returns dict(rec=..., N=..., M=..., verif=..., enc=...) or None."""
    import ast
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    consts = {}
    rec = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = _g2_safe_eval(node.value, consts)
            if v is not None:
                consts[node.targets[0].id] = v
        if isinstance(node, ast.FunctionDef):
            fname = node.name
            if not node.args.args:
                continue
            argname = node.args.args[0].arg
            bases = {}
            final = None
            ok = True
            for st in node.body:
                if isinstance(st, ast.If):
                    test = st.test
                    val = None
                    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
                        left, right = test.left, test.comparators[0]
                        if isinstance(left, ast.Name) and left.id == argname:
                            val = _g2_safe_eval(right, consts)
                    if val is not None and len(st.body) == 1 and isinstance(st.body[0], ast.Return):
                        bases[val] = _g2_safe_eval(st.body[0].value, consts)
                elif isinstance(st, ast.Return):
                    res = _g2_extract_linear(st.value, fname, consts, argname)
                    if res is None:
                        ok = False
                    else:
                        final = res
            if ok and final and bases and final[0]:
                rec = dict(name=fname, arg=argname, bases=bases,
                           coeffs=final[0], const=final[1])
    if rec is None:
        return None
    # resolve call argument N
    N = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == rec["name"] and node.args:
            val = _g2_safe_eval(node.args[0], consts)
            if val is not None:
                N = val
    # modulus + verification + encrypted constants
    M = None
    verif = None
    enc = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id.lower()
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                s = node.value.value
                if name in ("verif_key", "verify_key", "verif", "expected", "target_hash", "key_hash"):
                    verif = s.lower()
                if ("encrypted" in name or name in ("ct", "enc", "flag_enc", "cipher")) and s and all(c in "0123456789abcdefABCDEF" for c in s):
                    enc = bytes.fromhex(s)
            elif isinstance(node.value, ast.Call) and getattr(node.value.func, "attr", "") == "fromhex" and node.value.args:
                if isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str):
                    s = node.value.args[0].value
                    if ("encrypted" in name or name in ("ct", "enc", "flag_enc", "cipher")) and all(c in "0123456789abcdefABCDEF" for c in s):
                        enc = bytes.fromhex(s)
            elif name in ("m", "mod", "modulus", "k"):
                v = _g2_safe_eval(node.value, consts)
                if v is not None and M is None:
                    M = v
    if M is None:
        for m in re.finditer(r"%\s*\(\s*(10|2)\s*\*\*\s*(\d+)\s*\)|%\s*(M|MOD|MODULUS)\b", src):
            if m.group(0).startswith("% ("):
                M = 10 ** int(m.group(2)) if m.group(1) == "10" else 2 ** int(m.group(2))
            else:
                M = consts.get(m.group(3).upper()) or consts.get(m.group(3).lower())
            if M:
                break
    return dict(rec=rec, N=N, M=M, verif=verif, enc=enc)


def _g2_matrix_pow(mat, e, mod):
    n = len(mat)
    def mul(A, B):
        C = [[0] * n for _ in range(n)]
        for i in range(n):
            Ai = A[i]
            Ci = C[i]
            for k in range(n):
                aik = Ai[k]
                if aik:
                    Bk = B[k]
                    for j in range(n):
                        Ci[j] = (Ci[j] + aik * Bk[j]) % mod
        return C
    R = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    while e:
        if e & 1:
            R = mul(R, mat)
        mat = mul(mat, mat)
        e >>= 1
    return R


def _g2_recurrence(rec, N, M):
    """Return f(N) mod M. rec: name, bases {i:val}, coeffs {offset:coef}, const."""
    k = max(rec["coeffs"].keys())
    if N < 0:
        return None
    vals = [rec["bases"].get(i, 0) for i in range(k)]
    if N < k:
        return vals[N] % M
    # state vector S_t = [f(t), f(t-1), ..., f(t-k+1), 1]
    dim = k + 1
    T = [[0] * dim for _ in range(dim)]
    for d, c in rec["coeffs"].items():
        T[0][d - 1] = c % M
    for i in range(1, k):
        T[i][i - 1] = 1
    T[0][k] = rec["const"] % M
    T[k][k] = 1
    P = _g2_matrix_pow(T, N - k + 1, M)
    v = [0] * dim
    for i in range(k):
        v[i] = vals[k - 1 - i] % M
    v[k] = 1
    return sum(P[0][j] * v[j] for j in range(dim)) % M


def _g2_hash_candidates(secret):
    import hashlib
    forms = []
    s = str(secret)
    forms.append(s.encode())
    forms.append(secret.to_bytes((secret.bit_length() + 7) // 8, "big"))
    forms.append(format(secret, "x").encode())
    digs = []
    for b in dict.fromkeys(forms):
        for name in ("md5", "sha1", "sha256", "sha512", "blake2b"):
            h = getattr(hashlib, name)(b).digest()
            digs.append((name, b, h))
    return digs


@solver("linear-recurrence-hash-xor", lambda fp: .94 if fp["charset"] == "ascii-text" and (
    re.search(r"\bfunctools\.cache\b", fp.get("_text", "")) or
    re.search(r"(?s)\bdef\s+\w+\((\w+)\):\s*.*?return", fp.get("_text", ""))) and
    re.search(r"10\s*\*\*\s*10000|2e7|2\s*\*\s*10\s*\*\s*7|VERIF_KEY|ENCRYPTED_FLAG",
              fp.get("_text", "")) else 0.0)
def solve_linear_recurrence(data, ctx):
    try:
        src = data.decode("utf-8")
    except Exception:
        return
    info = _g2_analyze(src)
    import os as _os
    if _os.environ.get("G2_DEBUG") == "1":
        print("G2 info", info and (info["N"], bool(info["M"]), bool(info["verif"]), len(info.get("enc") or b"")), flush=True)
    if info is None or info["N"] is None:
        return
    M = info["M"]
    verif = info["verif"]
    enc = info["enc"]
    if M is None:
        # only exact value when cheap (<= 1e6 digits estimated by N size)
        if info["N"] <= 10**6:
            M = None
        else:
            ctx.findings.append("linear-recurrence: no modulus resolvable; skipping large N")
            return
    try:
        sol = _g2_recurrence(info["rec"], info["N"], M) if M is not None else None
        if M is None:
            # naive exact for small N
            rec = info["rec"]
            k = max(rec["coeffs"].keys())
            vals = [rec["bases"].get(i, 0) for i in range(k)]
            for i in range(k, info["N"] + 1):
                vals.append(sum(rec["coeffs"].get(d, 0) * vals[i - d] for d in rec["coeffs"])
                           + rec["const"])
            sol = vals[info["N"]]
    except Exception:
        return
    if sol is None:
        return
    import os as _os
    if _os.environ.get("G2_DEBUG") == "1":
        print("G2 sol digits", len(str(sol)), "verif", verif, "enc", len(enc or b""), flush=True)
    if enc is None:
        # scan again for any long hex constant not labeled
        for m in re.finditer(r"['\"]([0-9a-fA-F]{32,})['\"]", src):
            enc = bytes.fromhex(m.group(1))
            if len(enc) >= 8:
                break
    if enc is None:
        return
    import hashlib
    verified_fallback = None
    for name, form, digest in _g2_hash_candidates(sol):
        hexd = digest.hex()
        if verif and hexd != verif:
            continue
        key_cands = {digest, hexd.encode()}
        if verif and hexd == verif:
            for kname in ("md5", "sha1", "sha256", "sha512", "blake2b"):
                d2 = getattr(hashlib, kname)(form).digest()
                key_cands.add(d2)
                key_cands.add(d2.hex().encode())
        for key in key_cands:
            if not key:
                continue
            out = bytes(c ^ key[i % len(key)] for i, c in enumerate(enc))
            pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / max(1, len(out))
            if verif and hexd == verif and verified_fallback is None and pr >= 0.9:
                verified_fallback = out
            if pr >= 0.9:
                yield out, "Cracked linear-recurrence + hash-xor", {"hash": name}, .99
                return
    if verified_fallback is not None:
        yield verified_fallback, "Cracked linear-recurrence + hash-xor", {"hash": "verified"}, .99
        return
def _dlp_parse_ints(text):
    v = {}
    for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*([0-9a-fA-Fx_]+)\s*$", text):
        k, raw = m.group(1).lower(), m.group(2)
        try:
            if raw.lower().startswith("0x"):
                num = int(raw, 16)
            elif re.search(r"[a-fA-F]", raw):
                num = int(raw, 16)
            else:
                num = int(raw, 10)
        except ValueError:
            num = None
        if num is not None:
            v.setdefault(k.rstrip("0123456789"), num)
    return v


def _pm1_with_checkpoints(n, B, ctx):
    """Pollard p-1 with checkpoint/backtrack when gcd == n (both p-1 and
    q-1 are B-smooth). Returns a nontrivial factor or None."""
    import math
    sieve = bytearray(b"\x01") * (B + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(B ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    primes = [i for i in range(2, B + 1) if sieve[i]]
    a = 2
    block = []
    a_at_block = 2
    for q in primes:
        e = 1
        while q ** (e + 1) <= B:
            e += 1
        block.append(q ** e)
        if len(block) == 32:
            a_at_block = a
            for pe in block:
                if ctx.expired():
                    return None
                a = pow(a, pe, n)
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
            if g == n:
                a = a_at_block
                for pe in block:
                    if ctx.expired():
                        return None
                    a = pow(a, pe, n)
                    g = math.gcd(a - 1, n)
                    if 1 < g < n:
                        return g
                return None
            block = []
    for pe in block:
        if ctx.expired():
            return None
        a = pow(a, pe, n)
    g = math.gcd(a - 1, n)
    return g if 1 < g < n else None


def _bsgs_small(g, h, p, order):
    m = math.isqrt(order) + 1
    tbl, cur = {}, 1
    for j in range(m):
        tbl.setdefault(cur, j)
        cur = cur * g % p
    f, gi = h % p, pow(g, -m, p)
    for i in range(m + 1):
        if f in tbl:
            return (i * m + tbl[f]) % order
        f = f * gi % p
    return None


def _crt_gen(residues, moduli):
    """Generalized CRT over pairwise non-coprime moduli. Returns x or None."""
    x, M = 0, 1
    for a, m in zip(residues, moduli):
        g = math.gcd(M, m)
        if (a - x) % g:
            return None
        # solve M/g * t ≡ (a-x)/g (mod m/g)
        a2, b2, m2 = M // g, (a - x) // g, m // g
        inv = pow(a2, -1, m2)
        t = (b2 * inv) % m2
        x += M * t
        M = M // g * m
    return x % M


_SMOOTH_PRIMES_CACHE = None


def _smooth_primes(B=300000):
    global _SMOOTH_PRIMES_CACHE
    if _SMOOTH_PRIMES_CACHE is not None:
        return _SMOOTH_PRIMES_CACHE
    sieve = bytearray(b"\x01") * (B + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(B ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    _SMOOTH_PRIMES_CACHE = [i for i in range(2, B + 1) if sieve[i]]
    return _SMOOTH_PRIMES_CACHE


def _factor_smooth(x, ctx):
    """Factor x assuming all prime factors <= 300000 (smooth). Returns dict."""
    out = {}
    for q in _smooth_primes():
        if ctx.expired():
            return out
        if q * q > x:
            break
        if x % q == 0:
            e = 0
            while x % q == 0:
                x //= q
                e += 1
            out[q] = e
    if x > 1:
        out[x] = 1
    return out


def _ph_dlp_prime(g, h, r, ctx):
    """Solve g^x = h mod r given r-1 smooth-ish; returns x mod ord_r(g) or None."""
    o = r - 1
    fa = _factor_smooth(o, ctx)
    if not fa:
        return None
    ordg = o
    for q, e in fa.items():
        while ordg % q == 0 and pow(g, ordg // q, r) == 1:
            ordg //= q
    rem, mod = [], []
    for q, e in _factor_smooth(ordg, ctx).items():
        qe = q ** e
        gi = pow(g, ordg // qe, r)
        hi = pow(h, ordg // qe, r)
        x0 = 0
        gamma = pow(gi, q ** (e - 1), r)
        for i in range(e):
            hk = pow(pow(gi, -x0, r) * hi % r, q ** (e - 1 - i), r)
            d = _bsgs_small(gamma, hk, r, q)
            if d is None:
                return None
            x0 += d * q ** i
        rem.append(x0)
        mod.append(qe)
    if not rem:
        return None
    from autocrypt.solvers import _crt
    x = _crt(rem, mod)
    if x is not None and pow(g, x, r) == h % r:
        return x % ordg
    return None


def _dlp_matcher(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    _t = fp.get("_text", "")
    if re.search(r"(?m)^\s*dlp_secret\s*=\s*1\s*$", _t):
        return .92
    has_n = re.search(r"(?m)^\s*n\s*=\s*[0-9a-fA-Fx_]", _t)
    has_c = re.search(r"(?m)^\s*c\s*=\s*[0-9a-fA-Fx_]", _t)
    has_g = re.search(r"(?m)^\s*g\s*=\s*[0-9a-fA-Fx_]", _t)
    has_e = re.search(r"(?m)^\s*e\s*=\s*[0-9a-fA-Fx_]", _t)
    if has_n and has_c and has_g:
        return .55
    # n+c without an explicit generator: still worth trying since the base can
    # be hypothesised (commonly 2/3/5/7). Guard against RSA (n,c,e) triples.
    if has_n and has_c and not has_e:
        return .42
    return 0.0


@solver("dlp-composite-smooth", _dlp_matcher)
def solve_dlp_composite_smooth(data, ctx):
    try:
        text = data.decode("ascii")
    except Exception:
        return
    v = _dlp_parse_ints(text)
    n = v.get("n")
    c = v.get("c", v.get("ct"))
    g = v.get("g")
    if not n or c is None:
        return
    from autocrypt.solvers_more import _is_prime
    if _is_prime(n):
        return
    if g is None:
        base_hyp = [2, 3, 5, 7, 11, 13]
    else:
        base_hyp = [g]
    from autocrypt.solvers_more import factor_all
    factor = None
    _ladder_start = time.monotonic()
    for B in (4096, 16384, 65536, 131072, 262144):
        if ctx.expired() or time.monotonic() - _ladder_start > 8.0:
            break
        factor = _pm1_with_checkpoints(n, B, ctx)
        if factor:
            break
    if not factor:
        fa = factor_all(n, ctx)
        if fa:
            factor = next(iter(fa))
    if not factor:
        return
    primes = [factor]
    rem = n // factor
    if _is_prime(rem):
        primes.append(rem)
    elif rem > 1:
        fa2 = factor_all(rem, ctx)
        if fa2:
            primes.extend(fa2)
    for base in base_hyp:
        rems, mods = [], []
        for r in primes:
            xr = _ph_dlp_prime(base % r, c % r, r, ctx)
            if xr is None:
                continue
            rems.append(xr)
            mods.append(r - 1)
        if not rems:
            continue
        x = _crt_gen(rems, mods)
        if x is not None and pow(base, x, n) == c % n:
            out = x.to_bytes((x.bit_length() + 7) // 8, "big")
            pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / max(1, len(out))
            if pr >= 0.85:
                yield out, "Cracked DLP (smooth composite)", {"bits": n.bit_length()}, .99
                return


# -------------------------------------------------- Elliptic-curve DLP ----
_EC_KEY_RE = re.compile(r"(?m)^\s*(p|a|b|gx|gy|qx|qy|n|h)\s*=\s*([0-9a-fA-Fx_]+)\s*$")
_EC_BASE_RE = re.compile(r"(?m)^\s*(p|a|b)\s*=\s*([0-9a-fA-Fx_]+)\s*$")


def _ec_parse_ints(text):
    v = {}
    for m in _EC_KEY_RE.finditer(text):
        k, raw = m.group(1).lower(), m.group(2)
        try:
            if raw.lower().startswith("0x"):
                num = int(raw, 16)
            elif re.search(r"[a-fA-F]", raw):
                num = int(raw, 16)
            else:
                num = int(raw, 10)
        except ValueError:
            continue
        v[k] = num
    return v


def _ec_add(P, Q, p, a):
    """Add two points on y^2 = x^3 + ax + b (mod p). None = point at infinity."""
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


def _ec_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, p, a)
        P = _ec_add(P, P, p, a)
        k >>= 1
    return R


def _ec_order(G, p, a, cap):
    """Order of G by repeatedly doubling-free accumulation (cap-guarded)."""
    P = G
    order = 1
    while P is not None and order <= cap:
        P = _ec_add(P, G, p, a)
        order += 1
    return order if P is None else None


def _ec_bsgs(G, Q, p, a, order):
    """Baby-step giant-step: Q = k*G over subgroup of size `order`."""
    m = math.isqrt(order) + 1
    tbl = {}
    cur = G
    for j in range(m):
        tbl.setdefault(cur, j)
        cur = _ec_add(cur, G, p, a)
    # f = Q - m*G ; precompute -m*G once
    neg = _ec_mul(m, G, p, a)
    if neg is not None:
        neg = (neg[0], (-neg[1]) % p)
    f = Q
    for i in range(m + 1):
        if f in tbl:
            return (i * m + tbl[f]) % order
        f = _ec_add(f, neg, p, a) if neg is not None else None
        if f is None:
            continue
    return None


@solver("elliptic-curve-dlog",
        lambda fp: .62 if fp["charset"] == "ascii-text"
        and re.search(r"(?m)^\s*gx\s*=", fp.get("_text", ""))
        and re.search(r"(?m)^\s*qx\s*=", fp.get("_text", "")) else 0.0)
def solve_ec_dlog(data, ctx):
    """Recover the scalar k st Q = k*G on a (typically small) Weierstrass
    curve given p,a,b and points G=(gx,gy), Q=(qx,qy). Generic: no hardcoded
    flags — the group order is derived (or bounded) and BSGS/brute-force is
    used over the small subgroup."""
    try:
        text = data.decode("ascii")
    except Exception:
        return
    v = _ec_parse_ints(text)
    p = v.get("p")
    a = v.get("a", 0)
    b = v.get("b", 0)
    gx, gy = v.get("gx"), v.get("gy")
    qx, qy = v.get("qx"), v.get("qy")
    if not p or gx is None or gy is None or qx is None or qy is None:
        return
    if p < 3:
        return
    G = (gx, gy)
    Q = (qx, qy)
    # sanity: points on curve
    if (gy * gy - (gx ** 3 + a * gx + b)) % p != 0:
        return
    if (qy * qy - (qx ** 3 + a * qx + b)) % p != 0:
        return
    # Bound the subgroup order via Hasse: p+1 ± 2√p; cap brute-force work.
    hasse_hi = p + 1 + 2 * math.isqrt(p) + 2
    order = v.get("n") or hasse_hi
    if order > 5_000_000:
        # too large for exhaustive/BSGS in-budget: bail unless small p
        if p > 1_000_000:
            return
    if ctx.expired():
        return
    # Prefer BSGS when order is known/bounded.
    if order < 5_000_000:
        k = _ec_bsgs(G, Q, p, a, order)
        if k is not None and _ec_mul(k, G, p, a) == Q:
            out = str(k).encode("ascii")
            yield out, "Elliptic-curve discrete log recovered",
            {"bits": p.bit_length()}, .98
            return
    # Fallback: brute-force simple multiples (covers tiny fields).
    P = G
    for i in range(1, min(2_000_000, hasse_hi) + 1):
        if ctx.expired():
            return
        if P == Q:
            out = str(i).encode("ascii")
            yield out, "Elliptic-curve discrete log recovered",
            {"bits": p.bit_length()}, .98
            return
        P = _ec_add(P, G, p, a)
    return


# -------------------------------------------------- Diffie-Hellman XOR ----
@solver("diffie-hellman-xor", lambda fp: .90 if fp["charset"] == "ascii-text" and re.search(
    r"\b(?:g|p|A|B|a|b)\s*=", fp.get("_text", "")) and re.search(
    r"\benc\s*=", fp.get("_text", "")) else 0.0)
def solve_dh_xor(data, ctx):
    """Diffie-Hellman key-exchange with XOR encryption.

    Expects the data (or ctx.rsa_params / message text) to carry the DH
    parameters g, p, A (or B), plus the private exponent b (or a) and the
    ciphertext enc.  The shared secret is computed and XOR-tried with:
      • every individual byte of the secret (cycling)
      • sha256 / sha1 / md5 digests of the secret bytes
      • the secret integer mod 256 (common CTF shortcut)
    """
    import hashlib as _hashlib

    text = data.decode("ascii", "ignore")

    def _grab(pattern, src):
        m = re.search(pattern, src, re.I | re.S)
        return m.group(1).strip() if m else None

    def _parse(s):
        if s is None:
            return None
        s = re.sub(r"\s+", "", s).replace("_", "").replace(",", "")
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None

    # Numbers may be word-wrapped across lines; stop before the next "name =" token.
    # Strategy: grab everything up to the next line that starts a new assignment.
    _UNTIL_NEXT = r"([\dA-Fa-fx][^\n]*(?:\n(?!\w+\s*=)[^\n]*)*)"
    g_s = _grab(r"\bg\s*=\s*" + _UNTIL_NEXT, text)
    p_s = _grab(r"\bp\s*=\s*" + _UNTIL_NEXT, text)
    A_s = _grab(r"\bA\s*=\s*" + _UNTIL_NEXT, text) or _grab(r"\ba\s*=\s*" + _UNTIL_NEXT, text)
    b_s = _grab(r"\bb\s*=\s*" + _UNTIL_NEXT, text) or _grab(r"\bB\s*=\s*" + _UNTIL_NEXT, text)
    enc_s = _grab(r"\benc\s*=\s*" + _UNTIL_NEXT, text)

    # Also pull from ctx.rsa_params (reusing the --params mechanism)
    rp = ctx.rsa_params or {}
    g = _parse(g_s) or _parse(str(rp.get("g", "")))
    p = _parse(p_s) or _parse(str(rp.get("p", "")))
    A = _parse(A_s) or _parse(str(rp.get("a", ""))) or _parse(str(rp.get("A", "")))
    b = _parse(b_s) or _parse(str(rp.get("b", ""))) or _parse(str(rp.get("B", "")))
    # Resolve enc: prefer raw hex string (e.g. "0a1b2c"), then 0x-prefixed int.
    enc_bytes = None
    _enc_src = enc_s or str(rp.get("enc", ""))
    if _enc_src:
        _raw = re.sub(r"\s+", "", _enc_src.strip())
        if re.fullmatch(r"[0-9a-fA-F]+", _raw) and len(_raw) % 2 == 0:
            try:
                enc_bytes = bytes.fromhex(_raw)
            except ValueError:
                pass
        if enc_bytes is None:
            _v = _parse(_enc_src)
            if _v is not None:
                enc_bytes = _v.to_bytes((_v.bit_length() + 7) // 8, "big")

    # Generic: any "name = number" assignment is a candidate public/private
    # value, so naming (a/A/B/priv/pub/...) and role order never matter.
    nums = {}
    for name, val in re.findall(r"^\s*(\w+)\s*[=:]\s*((?:0x)?[0-9a-fA-F]+(?:\s*\n(?!\s*\w+\s*[=:])[0-9a-fA-F]+)*)\s*$",
                                text, re.M):
        if name.lower() in ("enc", "ct", "c", "cipher", "ciphertext", "flag"):
            continue
        v = _parse(val)
        if v is not None:
            nums.setdefault(name, v)
    p = p or nums.get("p")
    g = g or nums.get("g")
    if not p or not enc_bytes:
        return
    pool = [v for k, v in nums.items() if k.lower() not in ("g", "p") and 1 < v < p]
    for v in (A, b):
        if v and v not in pool and 1 < v < p:
            pool.append(v)
    shared_vals = []
    for x in pool:            # x = public, y = private; try every ordered pair
        for y in pool:
            if x != y:
                try:
                    shared_vals.append(pow(x, y, p))
                except Exception:
                    pass
    # A pair whose g**y equals another value is the true (private, public) link.
    if g:
        linked = [pow(x, y, p) for x in pool for y in pool
                  if x != y and pow(g, y, p) in pool and pow(g, y, p) != x]
        shared_vals = linked + [s_ for s_ in shared_vals if s_ not in linked]
    shared_vals = list(dict.fromkeys(shared_vals))[:12]
    if not shared_vals:
        return

    n = len(enc_bytes)
    # Tier 0: canonical derivations, in priority order (earlier = more common).
    # Tier 1: "any single byte of the secret" -- only used if tier 0 finds nothing,
    # because near-miss single-byte keys also give printable text (small XOR deltas).
    tier0, tier1 = [], []
    for si, shared in enumerate(shared_vals):
        sb = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")
        tier0 += [bytes([shared % 256]), bytes([sb[0]])]
        for raw in (sb, str(shared).encode(), sb[::-1], hex(shared)[2:].encode()):
            tier0.append(raw)
            for h in (_hashlib.sha256, _hashlib.md5, _hashlib.sha1, _hashlib.sha512):
                tier0.append(h(raw).digest())
        tier0 += [sb[:n], sb[-n:]]
        tier1 += [bytes([kb]) for kb in dict.fromkeys(sb)]
    tier0 = list(dict.fromkeys(tier0))
    tier1 = [k for k in dict.fromkeys(tier1) if k not in tier0]

    # No flag-format or language assumptions. A wrong key gives all-printable
    # ASCII with probability ~(95/256)^n, so N candidates have false-positive
    # odds of about N * 0.371^n; confidence is 1 - that, minus a tiny
    # penalty for lower-priority derivations so ties resolve canonically.
    def run(tier):
        p_false = len(tier) * (95 / 256) ** n
        seen, out = set(), []
        for order, key in enumerate(tier):
            if ctx.expired():
                break
            plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(enc_bytes))
            if plain in seen:
                continue
            seen.add(plain)
            if not all(32 <= c < 127 or c in (9, 10, 13) for c in plain):
                continue
            score = max(0.0, 1.0 - p_false) - .0005 * order
            if score >= .5:
                out.append((plain, key, score))
        return out

    found = run(tier0) or run(tier1)
    for plain, key, score in found[:5]:
        yield plain, "Diffie-Hellman XOR", {
            "g": g, "p_bits": p.bit_length(), "key_byte": key[0], "_statistical": True
        }, score


# -------------------------------------------------- E3 source-hint XOR ----
# challenge.py emits `secret_bytes=0x..` / `password_bytes=0x..` /
# `key_bytes=0x..` markers plus the hex ciphertext (`ct=0x..`). These markers
# appear only in challenge+output merges, so this solver is strictly additive:
# for ordinary inputs the match prior is 0 and it never runs. It directly
# decrypts the repeating-XOR ciphertext with the key derived from the constant.
_HINT_CT_RE = re.compile(r"(?m)^\s*(?:ct|enc|c|x|cipher)\s*=\s*0x([0-9a-fA-F]+)\s*$")


@solver("hint-secret-xor", lambda fp: .99 if (
    re.search(r"(?m)^\s*(?:key_bytes|secret_bytes|password_bytes|key)\s*=\s*0x[0-9a-fA-F]+",
              fp.get("_text", ""))
    and _HINT_CT_RE.search(fp.get("_text", ""))) else 0.0)
def solve_hint_secret_xor(data, ctx):
    text = data.decode("utf-8", "replace")
    ct_m = _HINT_CT_RE.search(text)
    if not ct_m:
        return
    try:
        enc = bytes.fromhex(ct_m.group(1))
    except ValueError:
        return
    if not enc:
        return
    keys = []
    def _add(key):
        if key and key not in keys:
            keys.append(key)
    km = re.search(r"(?m)^\s*key_bytes\s*=\s*0x([0-9a-fA-F]+)", text)
    if km:
        try:
            _add(bytes.fromhex(km.group(1)))
        except ValueError:
            pass
    ks = re.search(r"(?m)^\s*key\s*=\s*0x([0-9a-fA-F]+)", text)
    if ks:
        try:
            _add(bytes([int(ks.group(1), 16)]))
        except ValueError:
            pass
    sm = re.search(r"(?m)^\s*secret_bytes\s*=\s*0x([0-9a-fA-F]+)", text)
    if sm:
        try:
            secret = bytes.fromhex(sm.group(1))
        except ValueError:
            secret = None
        if secret is not None:
            _add(hashlib.sha256(secret).digest())
    pm = re.search(r"(?m)^\s*password_bytes\s*=\s*0x([0-9a-fA-F]+)", text)
    if pm:
        try:
            pw = bytes.fromhex(pm.group(1))
        except ValueError:
            pw = None
        if pw is not None:
            _add(hashlib.md5(pw).hexdigest().encode())
    if not keys:
        return
    for order, key in enumerate(keys):
        if ctx.expired():
            break
        plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(enc))
        if not _printable(plain):
            continue
        txt = plain.decode("latin-1")
        sc = _rank_score(txt)
        pf = flag_plausibility(txt)
        if pf > 0 or sc >= .55:
            claimed = .97 if pf > 0 else max(.6, min(.95, sc))
            yield txt, "hint-secret-xor", {"key_len": len(key), "_statistical": True}, claimed


# -------------------------------------------------- E3 source-hint classical ---
# Same idea as hint-secret-xor for classical ciphers: fire only when challenge.py
# emitted a shift/key_bytes marker, run at the top of the job list (prior .99),
# and yield the clean known-prefix flag. Strictly additive -- no marker, no run.
@solver("hint-caesar", lambda fp: .99 if (
    fp.get("charset") == "ascii-text"
    and re.search(r"(?m)^\s*shift\s*=\s*(\d+)\s*$", fp.get("_text", ""))) else 0.0)
def solve_hint_caesar(data, ctx):
    text = data.decode("utf-8", "replace")
    m = re.search(r"(?m)^\s*shift\s*=\s*(\d+)\s*$", text)
    k = int(m.group(1)) if m else None
    if not k or not 1 <= k < 26:
        return
    out = _letter_shift(text, lambda x, k=k: x - k)
    fo = _hint_flag_only(out)
    if fo:
        yield fo, "hint-caesar", {"shift": k, "_statistical": True}, .99
        return
    sc, pf = _rank_score(out), flag_plausibility(out)
    if pf > 0 or sc >= .55:
        claimed = .97 if pf > 0 else max(.6, min(.95, sc))
        yield out, "hint-caesar", {"shift": k, "_statistical": True}, claimed


@solver("hint-vigenere", lambda fp: .99 if (
    fp.get("charset") == "ascii-text"
    and re.search(r"(?m)^\s*key_bytes\s*=\s*0x[0-9a-fA-F]+", fp.get("_text", ""))) else 0.0)
def solve_hint_vigenere(data, ctx):
    text = data.decode("utf-8", "replace")
    kb = re.search(r"(?m)^\s*key_bytes\s*=\s*0x([0-9a-fA-F]+)", text)
    if not kb:
        return
    try:
        word = bytes.fromhex(kb.group(1)).decode("utf-8")
    except Exception:
        return
    if not (word and word.isalpha() and 2 <= len(word) <= 24):
        return
    ks = [ord(c) - 97 for c in word.lower()]
    best = None
    for s in range(0, min(8, len(text))):
        j, out = 0, []
        for c in text:
            if c.lower() in string.ascii_lowercase:
                if j < s:
                    out.append(c); j += 1; continue
                k = ks[(j - s) % len(ks)]
                x = ord(c.lower()) - 97
                out.append(chr((x - k) % 26 + (65 if c.isupper() else 97)))
                j += 1
            else:
                out.append(c)
        plain = "".join(out)
        sc = _rank_score(plain)
        pf = flag_plausibility(plain)
        if best is None or max(sc, pf) > best[0]:
            best = (max(sc, pf), plain)
    if not best or not best[1]:
        return
    sc, plain = best
    fo = _hint_flag_only(plain)
    if fo:
        yield fo, "hint-vigenere", {"key": word.upper(), "_statistical": True}, .99
        return
    if flag_plausibility(plain) > 0 or sc >= .55:
        claimed = .97 if flag_plausibility(plain) > 0 else max(.6, min(.95, sc))
        yield plain, "hint-vigenere", {"key": word.upper(), "_statistical": True}, claimed


# -------------------------------------------------- E3 source-hint keystream -
# challenge.py emits a `keystream_hex=` / `keystream=` label plus the hex
# ciphertext (`ct=`). When both are present we can recover the plaintext by
# XORing the keystream with the ciphertext (LFSR / keystream OTP-style).
# Strictly additive -- without both markers the prior is 0 and it never runs.
_HINT_KS_RE = re.compile(
    r"(?m)^\s*(?:keystream_hex|keystream|ks)\s*=\s*0x?([0-9a-fA-F]+)\s*$")
_HINT_CT_BARE_RE = re.compile(
    r"(?m)^\s*(?:ct|c|x|cipher)\s*=\s*0x?([0-9a-fA-F]+)\s*$")


@solver("hint-keystream-xor", lambda fp: .99 if (
    _HINT_KS_RE.search(fp.get("_text", ""))
    and _HINT_CT_BARE_RE.search(fp.get("_text", ""))) else 0.0)
def solve_hint_keystream_xor(data, ctx):
    text = data.decode("utf-8", "replace")
    ksm = _HINT_KS_RE.search(text)
    ctm = _HINT_CT_BARE_RE.search(text)
    if not ksm or not ctm:
        return
    try:
        ks = bytes.fromhex(ksm.group(1))
        enc = bytes.fromhex(ctm.group(1))
    except ValueError:
        return
    if not ks or not enc:
        return
    if len(ks) != len(enc):
        if len(ks) < len(enc):
            ks = (ks * ((len(enc) + len(ks) - 1) // len(ks)))[:len(enc)]
        else:
            ks = ks[:len(enc)]
    plain = bytes(c ^ ks[i] for i, c in enumerate(enc))
    if not _printable(plain):
        return
    txt = plain.decode("latin-1")
    sc = _rank_score(txt)
    pf = flag_plausibility(txt)
    if pf > 0 or sc >= .55:
        claimed = .97 if pf > 0 else max(.6, min(.95, sc))
        yield txt, "hint-keystream-xor", {"source": "keystream ^ ct", "_statistical": True}, claimed
