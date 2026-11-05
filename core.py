"""Fingerprinting, solver registry, and the bounded best-first search."""
from __future__ import annotations

import base64
import collections
import hashlib
import heapq
import math
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from scoring import (has_partial_english, flag_plausibility, is_flagish,
                     english_confidence, clear_english, leet_body_dict_fraction)

# Transpositions only reorder letters: if the input is already flag-shaped, a
# reordered copy that is also flag-shaped is coincidence, not a decryption.
_PERMUTING = {"rail fence", "scytale", "columnar transposition", "columnar transposition (brute)"}
# Fixed (keyless) letter substitutions: output shape proves the plaintext.
_FIXED_SUBSTITUTIONS = {"atbash"}
# Letter-wise ciphers never reorder letters: if their output lost separators
# (and the letter multiset is identical to the input's), we may safely
# re-interleave the input's separators. Transpositions (rail fence, columnar,
# scytale, ...) DO reorder letters, so interleaving would corrupt them.
_ORDER_PRESERVING = {
    "atbash", "rot13", "rot-13", "rot47", "caesar", "affine",
    "vigenere-dictionary", "vigenere-wordlist", "gronsfeld", "beaufort",
    "porta", "autokey", "variants-beaufort", "variant-beaufort",
    "monoalphabetic",
}
_KNOWN_PREFIXES = (
    "flag{", "ctf{", "picoctf{", "htb{", "ictf{", "dice{", "academy{", "thm{",
    "pwn{", "web{", "rev{", "misc{", "crypto{", "pwnable{", "hackthebox{",
    "dvctf{", "cyberhub{", "uiuctf{", "lactf{", "tjctf{", "corctf{", "sekai{",
    "justctf{", "idek{", "csc{", "n00bz{", "hkcert{", "fcsc{", "bctf{", "wgmy{",
)


SolverFn = Callable[[bytes, "Context"], Iterable[tuple[bytes | str, str, dict, float]]]
MatchFn = Callable[[dict], float]


@dataclass
class Solver:
    name: str
    matches: MatchFn
    solve: SolverFn


REGISTRY: list[Solver] = []


def solver(name: str, matches: MatchFn):
    """Register a solver. A new solver only needs a match rule and generator."""
    def decorate(fn: SolverFn):
        REGISTRY.append(Solver(name, matches, fn))
        return fn
    return decorate


@dataclass
class Context:
    deadline: float
    flag_regex: re.Pattern
    known_plaintext: str = ""
    wordlist: list[bytes] = field(default_factory=list)
    rsa_params: dict = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    strict: bool = False
    bug_log: list[tuple[str, str, str]] = field(default_factory=list)
    strict_failed: bool = False
    assess: Callable[[bytes | str], tuple[float, str]] | None = None
    progress_callback: Callable[[str], None] | None = None
    depth: int = 0
    flag_regex_explicit: bool = False
    jobs: int = 1
    pool: object | None = None
    exact_found: bool = False
    exact_time: float | None = None
    exact_chain: str = ""
    solver_times: dict = field(default_factory=dict)
    grace: float = 1.0
    speed: float = 1.0      # <1 for --fast (shorter per-solver slices), >1 for --deep
    heavy_names: frozenset = frozenset()  # solver names to skip under --fast

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def record_bug(self, name: str, e: BaseException):
        """Record an unexpected (non-control-flow) exception. Always logged;
        in strict mode the run must finish but exit non-zero."""
        typ = type(e).__name__
        import traceback as _tb
        tb = "".join(_tb.format_exception(type(e), e, e.__traceback__))[-1200:]
        self.bug_log.append((name, typ, tb))
        if self.strict:
            self.strict_failed = True


_BUG_TYPES = (NameError, AttributeError, TypeError, UnboundLocalError,
               KeyError, IndexError, ImportError, AssertionError)


def _solver_worker(args):
    """Runs one solver to completion/deadline in a pool worker. Returns
    (solver_name, [yields], error_or_None). Everything picklable."""
    import os
    os.environ["AUTOCRYPT_WORKER"] = "1"
    import re as _re
    name, blob, depth, deadline, flag_pattern, flag_explicit, known_plaintext, wordlist, rsa_params = args
    import core as _core
    import solvers  # noqa: F401  register registry
    ctx = _core.Context(
        deadline=deadline,
        flag_regex=_re.compile(flag_pattern, _re.DOTALL),
        flag_regex_explicit=flag_explicit,
        known_plaintext=known_plaintext,
        wordlist=wordlist,
        rsa_params=rsa_params,
        assess=None if False else __import__("scoring").assess)
    solver = next((s for s in _core.REGISTRY if s.name == name), None)
    if solver is None:
        return name, [], "solver not found"
    out = []
    try:
        for o, m, p, sc in solver.solve(blob, ctx):
            if len(out) >= 128:
                break
            out.append((o if isinstance(o, bytes) else str(o).encode("utf-8", "replace"),
                        str(m), dict(p or {}), float(sc)))
    except Exception as e:  # noqa: BLE001
        if isinstance(e, _BUG_TYPES):
            return name, [], f"[BUG {type(e).__name__}] {e!r}"
        return name, [], repr(e)
    return name, out, None


class SearchResult(list):
    """Backward-compatible list of candidates with an explicit search status."""

    def __init__(self, values=(), status="NOT_FOUND", failures=()):
        super().__init__(values)
        self.status = status
        self.failures = list(failures)


def _free_fixpoint(data: bytes):
    """Unambiguous-decoder fixpoint pre-pass: while the whole buffer strictly
    parses as hex/base64/base32/binary and the decoded output is plausible for
    the next layer, decode for free (no depth/time-slice cost). Returns
    (data, chain_names) or None."""
    import base64 as _b64
    chain = []
    cur = data
    for _ in range(6):
        try:
            txt = cur.decode("ascii")
        except Exception:
            break
        s = txt.strip()
        dec = None
        name = None
        # Disambiguation: the decoder alphabets overlap (any binary string is
        # valid hex; any base32 string is valid base64). Prefer the strictest
        # match so a pure 0/1 buffer decodes as binary (not junk hex) and an
        # uppercase base32 blob is not swallowed by the base64 branch.
        if re.fullmatch(r"[01\s]+", s):
            bits = re.sub(r"\s", "", s)
            if len(bits) >= 8 and len(bits) % 8 == 0:
                dec = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
                name = "binary"
        if dec is None and re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 \
                and len(s) >= 8 and not re.fullmatch(r"[01]+", s):
            try:
                dec = bytes.fromhex(s)
                name = "hex"
            except ValueError:
                pass
        if dec is None:
            # separator-tolerant hex: whitespace / , : ; / 0x-prefixed tokens
            toks = []
            for t in re.split(r"[\s,:;]+", s):
                t = t.strip().lower()
                if t.startswith("0x"):
                    t = t[2:]
                if t and re.fullmatch(r"[0-9a-f]{1,2}", t):
                    toks.append(t)
            if len(toks) >= 8 and len(toks) % 2 == 0:
                try:
                    dec = bytes.fromhex("".join(toks))
                    name = "hex"
                except ValueError:
                    pass
        if dec is None and re.fullmatch(r"[A-Z2-7]+=*", s.upper()) and len(s) >= 8:
            try:
                pad = s.upper() + "=" * ((-len(s)) % 8)
                dec = _b64.b32decode(pad)
                name = "base32"
            except Exception:
                pass
        if dec is None and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", s) and len(s) % 4 == 0 \
                and len(s) >= 8:
            try:
                pad = s + "=" * ((-len(s)) % 4)
                dec = _b64.b64decode(pad, validate=True)
                name = "base64"
            except Exception:
                pass
        if dec is None or not dec:
            break
        pr = sum(32 <= b < 127 or b in (9, 10, 13) for b in dec) / len(dec)
        if pr < 0.85:
            # only continue if the decode itself is the next encoding layer
            oknext = False
            try:
                nxt = dec.decode("ascii").strip()
                oknext = ((re.fullmatch(r"[0-9a-fA-F]+", nxt) and len(nxt) % 2 == 0) or
                          (re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", nxt) and len(nxt) % 4 == 0) or
                          re.fullmatch(r"[A-Z2-7]+=*", nxt.upper()))
            except Exception:
                pass
            # Binary chaining does not require the decoded payload to be text:
            # the next layer is the 0/1 ASCII string itself (e.g. hex layer
            # whose bytes are again '0'/'1' characters).
            if not oknext:
                try:
                    nxt2 = dec.decode("latin-1").strip()
                    bitslen = len(re.sub(r"\s", "", nxt2))
                    oknext = (re.fullmatch(r"[01\s]+", nxt2) and bitslen >= 8
                              and bitslen % 8 == 0)
                except Exception:
                    pass
            if not oknext:
                # A clean, unambiguous decode produced opaque (non-encoding)
                # payload: stop chaining but KEEP this decode as the fixpoint
                # result — it is ciphertext for the solvers to attack.
                chain.append(name)
                cur = dec
                break
        chain.append(name)
        cur = dec
    if not chain:
        return None
    return cur, chain


def _sample(data: bytes, limit: int = 100_000) -> bytes:
    return data if len(data) <= limit else data[:limit]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _ic(data: bytes) -> float:
    letters = [x for x in data.lower() if 97 <= x <= 122]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = collections.Counter(letters)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def fingerprint(data: bytes) -> dict:
    """Cheap structural statistics; expensive solving is deliberately separate."""
    s = _sample(data)
    try:
        text = s.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    stripped = text.strip()
    compact = re.sub(r"\s+", "", stripped)
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in s) / max(1, len(s))
    classes = []
    if not data:
        charset = "empty"
    elif not text:
        charset = "binary"
    else:
        if (re.fullmatch(r"[0-9a-fA-F\s]+", text) and
                len(re.sub(r"\s", "", text)) >= 2 and
                len(re.sub(r"\s", "", text)) % 2 == 0):
            classes.append("hex")
        else:
            # hex tokens separated by whitespace / , : ; / 0x prefixes
            # (e.g. "c6 c4 c6 c3" or "0xc6,0xc4"). Tokens must be whole
            # 1-2 hex-digit units, so English words never qualify.
            _sep = [t for t in re.split(r"[\s,:;]+", text) if t]
            hex_tok = [t for t in _sep
                       if re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,2}", t)]
            if len(_sep) >= 8 and len(hex_tok) >= 0.7 * len(_sep):
                classes.append("hex")
        if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}\s*", text) and len(compact) % 4 == 0:
            classes.append("base64")
        if re.fullmatch(r"[A-Z2-7]+=*\s*", text.upper()) and len(compact) >= 8:
            classes.append("base32")
        if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}\s*", text) and "+" not in text and "/" not in text:
            classes.append("base64url")
        if re.fullmatch(r"[A-Za-z0-9]+", compact) and len(compact) >= 8:
            classes.append("base58/base62")
        if re.fullmatch(r"[!-u]*", compact) and len(compact) >= 8:
            classes.append("base85")
        if re.fullmatch(r"[01\s]+", text) and len(compact) >= 8:
            classes.append("binary")
        if re.fullmatch(r"[0-7\s]+", text) and len(compact) >= 6:
            classes.append("octal")
        if re.fullmatch(r"\d{1,3}(?:[\s,;]+|$)+", text) and len(re.findall(r"\d+", text)) > 1:
            classes.append("decimal")
        if re.fullmatch(r"[.\-/\s]+", text) and ("." in text or "-" in text):
            classes.append("morse")
        if re.search(r"%[0-9a-fA-F]{2}", text):
            classes.append("url")
        if re.search(r"=[0-9A-Fa-f]{2}|=\r?\n", text):
            classes.append("quoted-printable")
        if "-----BEGIN " in text:
            classes.append("pem")
        parts = text.split(".")
        if len(parts) == 3 and parts[0] and parts[1]:
            classes.append("jwt")
        if re.fullmatch(r"\s*\d{1,2}(?:[\s,.-]+\d{1,2})+\s*", text):
            classes.append("a1z26/polybius")
        if re.fullmatch(r"[ABab\s]+", text) and len(re.sub(r"\s", "", text)) >= 5:
            classes.append("bacon")
        if re.fullmatch(r"[1-5\s]+", text) and len(compact) >= 4 and len(compact) % 2 == 0:
            classes.append("polybius")
        # Real text never contains stray control bytes (only tab/newline/CR).
        # Blobs that are mostly printable but carry control bytes (e.g. XOR
        # ciphertext over printable range) are not text: classifying them as
        # ascii-text gates out the XOR solvers (which normally skip English).
        ctl = sum(0 <= c < 32 and c not in (9, 10, 13) for c in s)
        if printable > 0.9 and ctl == 0:
            charset = "ascii-text"
        else:
            charset = "mixed"

    hypotheses: dict[str, float] = {}
    for label, prior in (
        ("hex", .92), ("base64", .90), ("base64url", .78), ("base32", .84),
        ("base58/base62", .50), ("base85", .42), ("binary", .82), ("octal", .78),
        ("decimal", .78), ("morse", .92), ("url", .96), ("quoted-printable", .94),
        ("pem", .99), ("jwt", .99), ("a1z26/polybius", .55), ("bacon", .48),
        ("polybius", .58),
    ):
        if label in classes:
            hypotheses[label] = prior
    magic = []
    if data.startswith(b"\x1f\x8b"):
        magic.append("gzip")
        hypotheses["gzip"] = .99
    if len(data) >= 2 and data[0] == 0x78 and data[1] in (0x01, 0x5e, 0x9c, 0xda):
        magic.append("zlib")
        hypotheses["zlib"] = .96
    if data.startswith(b"-----BEGIN "):
        magic.append("PEM")
    if len(s) >= 32:
        blocks = [s[i:i + 16] for i in range(0, len(s) - 15, 16)]
        if len(blocks) != len(set(blocks)):
            magic.append("repeated 16-byte blocks (possible ECB)")
    hashes = []
    if re.fullmatch(rb"[0-9a-fA-F]{32}", data.strip()):
        hashes.append("MD5 or NTLM")
    elif re.fullmatch(rb"[0-9a-fA-F]{40}", data.strip()):
        hashes.append("SHA-1")
    elif re.fullmatch(rb"[0-9a-fA-F]{64}", data.strip()):
        hashes.append("SHA-256")
    elif re.fullmatch(rb"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", data.strip()):
        hashes.append("bcrypt")
    from filetypes import detect_filetype
    filetype = detect_filetype(data)
    if filetype and filetype not in magic:
        magic.append(filetype)
    return {
        "length": len(data), "entropy": _entropy(s), "charset": charset,
        "printable": printable, "ic": _ic(s), "classes": classes,
        "hypotheses": sorted(hypotheses.items(), key=lambda x: -x[1]),
        "prior_map": hypotheses, "magic": magic, "hashes": hashes,
        "filetype": filetype, "_text": text, "_head": s[:64],
    }


def _consistent_flag_recovery(method_base, params, data_text, candidate):
    """Return True if `candidate` is really the transform of `data_text` that
    the claimed method+params describe (guards against junk flag-shaped rows)."""
    def letters(s):
        return "".join(ch.lower() for ch in s if ch.isalpha())
    try:
        base = method_base.lower()
        if base == "atbash":
            return candidate == data_text.translate(str.maketrans(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"))
        if base in ("rot13", "rot-13"):
            return letters(candidate) == letters(data_text.translate(str.maketrans(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM")))
        if base == "rot47":
            return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                           for c in candidate) == data_text
        if base == "caesar":
            k = params.get("shift", params.get("key"))
            c = "".join(chr(65 + (ord(ch) - 65 + int(k)) % 26) if "A" <= ch <= "Z"
                         else chr(97 + (ord(ch) - 97 + int(k)) % 26) if "a" <= ch <= "z"
                         else ch for ch in candidate)
            return letters(c) == letters(data_text)
        if base == "affine":
            a, b = int(params.get("a", 1)), int(params.get("b", 0))
            c = "".join(chr(65 + ((ord(ch) - 65) * a + b) % 26) if "A" <= ch <= "Z"
                         else chr(97 + ((ord(ch) - 97) * a + b) % 26) if "a" <= ch <= "z"
                         else ch for ch in candidate)
            return letters(c) == letters(data_text)
        if base in ("vigenere-dictionary", "vigenere-wordlist"):
            key = params.get("key", "")
            out, j = [], 0
            for ch in candidate:
                if ch.isalpha():
                    k = ord(key[j % len(key)]) - ord("A")
                    b = ord("A") if ch.isupper() else ord("a")
                    out.append(chr(b + (ord(ch) - b + k) % 26))
                    j += 1
                else:
                    out.append(ch)
            return letters("".join(out)) == letters(data_text)
        if base == "gronsfeld":
            key = params.get("key", "")
            out, j = [], 0
            for ch in candidate:
                if ch.isalpha():
                    k = int(key[j % len(key)])
                    b = ord("A") if ch.isupper() else ord("a")
                    out.append(chr(b + (ord(ch) - b + k) % 26))
                    j += 1
                else:
                    out.append(ch)
            return letters("".join(out)) == letters(data_text)
        if base in ("beaufort", "porta"):
            key = params.get("key", "")
            try:
                from solvers_pack7 import _beaufort_decrypt, _porta_decrypt
                # For Porta which is self-inverse; Beaufort forward:
                # c = (k - p) % 26.
                if base == "porta":
                    fn = _porta_decrypt
                    return letters(fn("".join(ch for ch in candidate if ch.isalpha()).upper(), key)) == \
                        letters(data_text)
                out = "".join(chr(65 + (ord(key[i % len(key)]) - 65 - (ord(ch) - 65)) % 26)
                               for i, ch in enumerate("".join(ch for ch in candidate if ch.isalpha()).upper()))
                return letters(out) == letters(data_text)
            except Exception:
                return True
    except Exception:
        return True
    return True


def search(data: bytes, ctx: Context, top: int = 5, max_depth: int = 6) -> SearchResult:
    """Best-first layered decode search, bounded by depth, time, and content hashes."""
    # Importing registers built-in solvers while keeping this module reusable.
    import solvers  # noqa: F401

    heap: list[tuple[float, int, bytes, tuple[str, ...], float, int]] = []
    import os as _os
    try:
        ctx.grace = float(_os.environ.get("G1B_GRACE", "1.0"))
    except Exception:
        ctx.grace = 1.0
    global _search_t0
    _search_t0 = time.monotonic()
    serial = 0
    heapq.heappush(heap, (-1.0, serial, data, (), 1.0, 0))
    visited = {hashlib.sha256(data).digest()}
    results: dict[bytes, dict] = {}
    ctx.failures.clear()
    try:
        id_text = data.decode("utf-8", "replace")
        id_match = ctx.flag_regex.search(id_text) if len(data) <= 100_000 else None
        if id_match and sum(c.isprintable() or c in "\r\n\t" for c in id_text) / max(1, len(id_text)) >= .9:
            id_plaus = flag_plausibility(id_text)
            id_rec = {"chain": "as-is (input already contains a flag-shaped string)",
                      "plaintext": id_text, "confidence": round(max(.96, .62 + .35 * id_plaus), 4),
                      "is_flag": True,
                      "_reason": f"Input is already flag-shaped; body plausibility {id_plaus:.2f}.",
                      "_raw": data}
            if id_match.group(0).lower().startswith(_KNOWN_PREFIXES) and top > 0:
                id_rec["confidence"] = .99
                return SearchResult([id_rec], "FOUND", ctx.failures)
            results[data] = id_rec
    except Exception:
        pass
    decoder_names = {
        "base16", "hex", "hex-in-text", "base32", "base64", "base64url", "base58", "base85",
        "ascii85", "url", "binary", "octal", "decimal bytes", "morse",
        "quoted-printable", "a1z26", "bacon", "polybius", "pem/base64",
        "gzip", "zlib", "jwt payload decode", "bytes-literal", "int-list",
        "hexdump", "radix-ascii", "custom-base", "crt", "reverse-words",
        "reverse-each-word", "two-symbol binary", "dna", "braille",
        "base32hex", "crockford", "swapped-case base64", "z85",
        "extra-encodings",
        "base45", "base36", "uuencode", "brainfuck", "nato phonetic",
        "appended data", "carved file", "zip entry", "lsb steganography",
        "qr code",
    }
    _post_exact = 0
    while heap and not ctx.expired():
        if ctx.exact_found and _post_exact >= 8:
            break
        _, _, blob, chain, chain_prior, depth = heapq.heappop(heap)
        if ctx.exact_found:
            _post_exact += 1
        if depth >= max_depth:
            continue
        ctx.depth = depth
        fix = _free_fixpoint(blob)
        if fix and not ctx.exact_found:
            newdata, names = fix
            if newdata != blob and len(newdata) < len(blob):
                digest2 = hashlib.sha256(newdata).digest()
                if digest2 not in visited:
                    visited.add(digest2)
                    serial += 1
                    # The free fixpoint node must not be starved behind
                    # shallow single-step guesses: never penalize it, give it
                    # a mild depth boost.
                    priority = chain_prior * (1.0 + 0.1 * depth)
                    heapq.heappush(heap, (-priority, serial, newdata,
                                          chain + tuple(names), priority, depth + 1))
        fp = fingerprint(blob)
        input_flag = bool(ctx.flag_regex.search(blob.decode("latin-1")))
        input_plaus = flag_plausibility(blob.decode("latin-1")) if input_flag else 0.0
        jobs = []
        for item in REGISTRY:
            try:
                prior = float(item.matches(fp))
            except Exception:
                prior = 0.0
            if prior > 0:
                jobs.append((prior, item))
        jobs.sort(key=lambda x: -x[0])
        jobs = jobs[:40]
        precomp = None
        if ctx.pool is not None and ctx.jobs > 1 and len(jobs) >= 2 and len(blob) >= 128 \
                and fp.get("charset") != "ascii-text":
            args = [(it.name, blob, depth, ctx.deadline, ctx.flag_regex.pattern,
                     ctx.flag_regex_explicit, ctx.known_plaintext,
                     list(ctx.wordlist)[:2000], ctx.rsa_params)
                    for _, it in jobs]
            futures = [ctx.pool.submit(_solver_worker, ar) for ar in args]
            precomp = {it.name: fu for (_, it), fu in zip(jobs, futures)}
        encoding_classes = {
            "hex", "base64", "base64url", "base32", "binary", "octal",
            "decimal", "morse", "url", "quoted-printable", "pem",
            "a1z26/polybius", "bacon", "polybius",
        }
        fingerprints_as_encoding = bool(
            fp["magic"] or encoding_classes.intersection(fp["classes"])
        )
        previous_method = chain[-1].split("(", 1)[0].lower() if chain else ""
        for prior, item in jobs:
            if ctx.expired():
                break
            # --fast: skip the most expensive brute-force solvers; they burn
            # slices that are better spent on the fast deterministic ones.
            if ctx.speed < 1 and item.name in ctx.heavy_names:
                continue
            if item.name == "monoalphabetic-substitution":
                # Run only on raw input or on the output of a decoder; a
                # preceding classical step (caesar, affine, ...) is noise.
                if chain and any(step.split("(", 1)[0].lower() not in decoder_names
                                 for step in chain):
                    continue
                if fingerprints_as_encoding:
                    continue
            if ctx.progress_callback:
                try:
                    ctx.progress_callback(item.name)
                except Exception:
                    pass
            best_seen = max((r["confidence"] for r in results.values()), default=0.0)
            if item.name == "columnar-transposition" and best_seen >= .72:
                continue
            if item.name == "monoalphabetic-substitution" and best_seen >= .98:
                continue
            if item.name == "playfair" and best_seen >= .72:
                continue
            try:
                # Per-solver time share: give each solver at most ~4s so
                # low-prior solvers still get a slice of the global budget.
                prev_deadline = ctx.deadline
                _item_start = time.monotonic()
                if item.name == "dlp-composite-smooth" and re.search(
                        r"(?m)^\s*dlp_secret\s*=\s*1\s*$",
                        fp.get("_text", "")) and not ctx.expired():
                    ctx.deadline = min(prev_deadline, time.monotonic() + 45.0 * ctx.speed)
                elif item.name == "RSA" and re.search(
                        r"\b(?:n|modulus)\s*[:=]\s*(0x[0-9a-f]+|\d+)",
                        fp.get("_text", "")) and not ctx.expired():
                    # Factoring 96-300-bit semiprimes is deterministic work
                    # that can exceed the default 4s slice; give the RSA
                    # solver room (still bounded by the global deadline).
                    ctx.deadline = min(prev_deadline, time.monotonic() + 30.0 * ctx.speed)
                else:
                    ctx.deadline = min(prev_deadline, time.monotonic() + 4.0 * ctx.speed)
                try:
                    if precomp is not None and item.name in precomp:
                        _n, presolved, err = precomp[item.name].result()
                        if err:
                            ctx.failures.append(f"{item.name}: {err}")
                        yielded = iter(presolved)
                    else:
                        yielded = item.solve(blob, ctx)
                finally:
                    ctx.deadline = prev_deadline
                    ctx.solver_times[item.name] = (
                        ctx.solver_times.get(item.name, 0.0) + time.monotonic() - _item_start)
                # Adaptive per-solver slice: if a solver is STILL making
                # progress (produced a candidate) near the end of its slice
                # and the global deadline has room, extend it ONCE by up to
                # 2x. This keeps deterministic enumeration work from being
                # cut short just because the machine is momentarily busy.
                _slice_end = time.monotonic() + 4.0 * ctx.speed
                _extended = False
                _n_yields = 0
                for plain, method, params, claimed_score in yielded:
                    if ctx.expired():
                        now = time.monotonic()
                        if (not _extended and _n_yields > 0
                                and now >= _slice_end - 2.0 * ctx.speed
                                and prev_deadline - now > 4.0 * ctx.speed):
                            ctx.deadline = min(prev_deadline, now + 4.0 * ctx.speed)
                            _extended = True
                            continue
                        break
                    _n_yields += 1
                    out = plain if isinstance(plain, bytes) else str(plain).encode("utf-8", "replace")
                    score, reason = ctx.assess(out) if ctx.assess else (float(claimed_score), "")
                    text = out.decode("utf-8", "replace")
                    letters = sum(ch.isalpha() for ch in text)
                    partial = has_partial_english(text)
                    if partial:
                        score = min(score, .60)
                        if letters >= 20:
                            reason = "Partial solve: several words are not recognizable English"
                        elif not reason.startswith("LOW CONFIDENCE"):
                            reason = (f"LOW CONFIDENCE: only {letters} letters; "
                                      "statistics are unreliable.")
                    raw_params = dict(params or {})
                    relative_candidate = bool(params.pop("_relative_candidate", False)) if params else False
                    statistical = bool(params.pop("_statistical", False)) if params else False
                    is_flag = False       # certain: stop the search here
                    flag_shaped = False   # looks like a flag but not certain: rank, keep searching
                    # English-format reconstruction: when a classical letter transform
                    # produced a separator-less candidate from a ciphertext that had
                    # spaces/punctuation (and identical letter order), re-interleave
                    # the original separators so the English decode keeps its shape.
                    # Only for letter-wise ciphers: transpositions reorder letters,
                    # so interleaving would destroy the recovery.
                    if (not is_flag and not flag_shaped
                            and method.split("(", 1)[0].lower().strip() in _ORDER_PRESERVING):
                        try:
                            src_text = blob.decode("utf-8", "replace")
                            src_letters = "".join(ch for ch in src_text if ch.isalpha())
                            if src_letters and len(src_letters) == len("".join(ch for ch in text if ch.isalpha())):
                                merged = []
                                it = iter(ch for ch in text if ch.isalpha())
                                for ch in src_text:
                                    if ch.isalpha():
                                        merged.append(next(it))
                                    else:
                                        merged.append(ch)
                                merged_text = "".join(merged)
                                if merged_text != text:
                                    text = merged_text
                        except Exception:
                            pass
                    if relative_candidate and score < .62 and not partial:
                        reason = ("LOW CONFIDENCE: this was the strongest exhaustive-key candidate, "
                                  "but absolute English evidence is weak.")
                    if params:
                        detail = ",".join(f"{k}={v}" for k, v in sorted(params.items()))
                        method = f"{method}({detail})"
                    base_method = method.split("(", 1)[0].lower().strip()
                    # Key-recovery attacks whose plaintext passed a content-agnostic
                    # statistical test (not English, not flag-shaped) keep their own score.
                    recovered = method.lower().startswith((
                        "rsa ", "cracked ", "jwt hs256", "known-plaintext", "diffie-hellman",
                    ))
                    flag_match = ctx.flag_regex.search(text)
                    # A printable, flag-shaped recovery is confirmed evidence on
                    # its own, even when the body is underscore/leet-heavy and
                    # is_flagish() (plausibility-gated) rejects it.
                    _flagout_ok = bool(
                        flag_match and flag_match.group(0).isascii()
                        and flag_match.group(0).isprintable()
                        and sum(c.isprintable() or c in "\r\n\t" for c in text)
                        / max(1, len(text)) >= 0.90
                        and "\ufffd" not in text)
                    if statistical:
                        score = max(0.0, min(1.0, float(claimed_score)))
                        reason = ("Key search ranked by a plaintext model; confidence reflects "
                                  "the margin over the next-best key.")
                    elif recovered and partial:
                        score = min(score, .60)
                    elif recovered:
                        if statistical:
                            # Verified attack result ranked by its plaintext
                            # model: keep the solver's claimed confidence.
                            score = max(0.0, min(1.0, float(claimed_score)))
                        # Only confirm an "exact" recovery as high-confidence when
                        # it is genuinely flag-shaped, clearly English, or a short
                        # canonical attack verdict (e.g. "k=7", "d=5 k=23").
                        _tech = (len(text) < 80 and sum(c.isprintable() for c in text) /
                                 max(1, len(text)) > 0.95 and
                                 any(c in "=,;:" for c in text))
                        # A verified recovery whose output is flag-shaped and
                        # printable is confirmed even when the flag body is
                        # short and non-dictionary (e.g. rsa_factored
                        # 'ged{a1}'): verification already proved the attack.
                        _fm = ctx.flag_regex.search(text)
                        _pok = bool(
                            _fm and _fm.group(0).isascii()
                            and _fm.group(0).isprintable()
                            and sum(c.isprintable() or c in "\r\n\t" for c in text)
                            / max(1, len(text)) >= 0.90
                            and "\ufffd" not in text)
                        if is_flagish(text) or clear_english(text) or _tech or _pok:
                            score = .98
                            reason = (f"LOW CONFIDENCE: only {letters} letters; statistics are unreliable. "
                                      "Exact attack/crib recovered the plaintext.") if letters < 20 else (
                                          "Recovered by an exact attack or supplied crib.")
                        else:
                            score = min(score, 0.55)
                            reason = "Recovered candidate is not recognizable text; not confirmed."
                    # An "exact" attack whose output is not readable plaintext
                    # (e.g. a false-positive Franklin-Reiter on accidental small
                    # labels, printing control bytes) is not evidence: demote it
                    # below the display floor and strip its recovered trust.
                    recovered_bad = False
                    full_chain = chain + (method,)
                    printable_ratio = (sum(c.isprintable() or c in "\r\n\t" for c in text) /
                                       max(1, len(text)))
                    is_flag = False       # certain: stop the search here
                    flag_shaped = False   # looks like a flag but not certain: rank, keep searching
                    authoritative = False  # fixed substitution on a flag-shaped input: rank top
                    strong_recovery = False  # transposition recovered the flag: rank above substitutions
                    decoder_unknown = False  # decoder output, flag-shaped, unknown prefix: rank, keep searching
                    if flag_match:
                        match_text = flag_match.group(0)
                        out_printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
                        printable_ok = (match_text.isascii() and match_text.isprintable()
                                        and out_printable >= .90 and "\ufffd" not in text)
                        if ctx.flag_regex_explicit or ctx.flag_regex.pattern != r"\w{1,40}\{.*?\}":
                            is_flag = True    # user-supplied pattern is authoritative
                        elif printable_ok:
                            exact_decode = (method.split("(", 1)[0].lower().strip() in decoder_names
                                            and not input_flag)
                            if ((match_text.lower().startswith(_KNOWN_PREFIXES) or recovered)
                                    and (is_flagish(text) or _flagout_ok)
                                    and len(match_text) >= 0.9 * max(1, len(re.sub(r"\s", "", text)))):
                                is_flag = True
                            elif is_flagish(text):
                                method_name = method.split("(", 1)[0].lower().strip()
                                if input_flag and method_name in _FIXED_SUBSTITUTIONS and \
                                        flag_plausibility(text) > input_plaus + 0.05:
                                    # The input was already flag-shaped and a fixed letter
                                    # substitution (e.g. atbash) produced a flag-shaped output
                                    # that is clearly more plausible than the ciphertext:
                                    # that is the genuine decrypted flag, not a coincidence. Rank
                                    # it top instead of exiting, so a genuine known-prefix recovery
                                    # from a later cipher still wins.
                                    flag_shaped = True
                                    authoritative = True
                                elif input_flag and method_name in _FIXED_SUBSTITUTIONS:
                                    # Fixed substitution on a flag-shaped input that does NOT
                                    # improve plausibility (e.g. atbash of a flag that is not
                                    # atbash-encoded) is just a transformed copy: rank normally,
                                    # never outrank the input-as-is.
                                    flag_shaped = True
                                elif method_name in _PERMUTING:
                                    # Transpositions only reorder letters, so a reordered copy
                                    # of an already flag-shaped input is coincidence, not a
                                    # decryption -- unless the transposition genuinely moved
                                    # the flag: the recovered flag starts at index 0, covers
                                    # essentially the whole buffer, and its leet body is a
                                    # real dictionary improvement over the input (letter
                                    # substitutions keep the input's brace position and often
                                    # just scramble the body into junk).
                                    nonws = len(re.sub(r"\s", "", text))
                                    dict_gain = (leet_body_dict_fraction(text) -
                                                 leet_body_dict_fraction(blob.decode("latin-1")))
                                    if (text.startswith(match_text) and nonws > 0 and
                                            len(match_text) >= .9 * nonws and dict_gain > 0):
                                        flag_shaped = True
                                        strong_recovery = True
                                else:
                                    flag_shaped = True
                                    # A decoder that produced a flag-shaped output with an
                                    # UNKNOWN prefix (e.g. base64 -> "XYZ{...}") is a strong
                                    # candidate but not proof: rank it at floor .95 and keep
                                    # searching so later layers (Caesar/ROT/XOR) can still win.
                                    decoder_unknown = exact_decode
                    # Evidence gate for flag-shaped rows: a genuine recovery
                    # reorganizes/decodes the body into real dictionary words
                    # (leet-aware) and covers essentially the whole buffer.
                    ev_cover = 0.0
                    ev_dgain = 0.0
                    if flag_shaped:
                        nonws_len_ev = max(1, len(re.sub(r"\s", "", text)))
                        ev_cover = len(match_text) / nonws_len_ev
                        ev_dgain = (leet_body_dict_fraction(text) -
                                    leet_body_dict_fraction(blob.decode("latin-1")))
                    strong_evidence = flag_shaped and ev_cover >= 0.9 and ev_dgain > 0
                    recovered_bad = bool(recovered) and not (is_flag or flag_shaped) \
                        and printable_ratio < 0.9
                    if recovered_bad:
                        score = min(score, 0.40)
                    if is_flag:
                        score = max(score, .95)  # authoritative match
                    elif flag_shaped:
                        nonws_len = max(1, len(re.sub(r"\s", "", text)))
                        cover = len(match_text) / nonws_len if nonws_len else 1.0
                        classical_steps = sum(
                            1 for s in full_chain
                            if s.split("(", 1)[0].lower() not in decoder_names)
                        if cover < 0.85 or classical_steps > 1:
                            # Not a clean single-stage recovery: either the flag
                            # match covers only part of the buffer (junk prefix
                            # outside the {…} shape) or the result required
                            # several stacked classical transforms. Keep it
                            # visible but below the as-is floor and genuine
                            # recoveries.
                            score = max(score, .62 + .35 * flag_plausibility(text))
                            score = min(score, 0.95)
                            reason = ("Flag-shaped substring (partial coverage or "
                                      "multi-step classical chain); not a clean recovery.")
                        else:
                            plaus = flag_plausibility(text)
                            if input_flag:
                                # The input was already flag-shaped, so a transformed copy must look
                                # clearly better than the original before it is preferred.
                                plaus = max(0.0, plaus - input_plaus - .1)
                            score = max(score, .62 + .35 * plaus)
                            if strong_recovery:
                                # Strong transposition recovery: reward the leet-body
                                # dictionary gain over the ciphertext (real evidence),
                                # floored just above the as-is floor so the genuine
                                # rail beats the input even when the gain is small.
                                dgain = (leet_body_dict_fraction(text) -
                                         leet_body_dict_fraction(blob.decode("latin-1")))
                                score = max(score, 0.97,
                                            0.86 + 0.12 * min(1.0, dgain / 0.4))
                            elif strong_evidence:
                                # The body genuinely improved into dictionary words:
                                # a real recovery, not a scramble. Allow it above
                                # the as-is floor.
                                score = max(score, 0.97)
                            elif authoritative:
                                score = max(score, .95)
                            elif decoder_unknown:
                                # Exact decodes of encoded data: the transform is
                                # content-agnostic, so the full-buffer result is
                                # strong regardless of the body's dictionary score.
                                score = max(score, 0.97 if cover >= 0.9 else 0.95)
                            reason = (f"Flag-shaped output (any prefix accepted); body plausibility "
                                      f"{plaus:.2f}. Other shifts/keys may also look like flags.")
                    # Anti-noise gate: a non-flag candidate that is not clearly
                    # English must never outrank a real English decode. Cap it
                    # below the 0.60 display/retention floor.
                    if not (is_flag or flag_shaped or recovered) and english_confidence(text) < 0.35:
                        score = min(score, 0.55)
                    # A statistical boost (0.55 + 0.35·ec) must not let a
                    # candidate that merely has English-L letter frequencies (no
                    # real dictionary words) outrank genuine English or a flag
                    # recovery. Cap it at the English decode floor as well.
                    # Deterministic direct decodes (Enigma with full settings) are
                    # exact and keep top confidence.
                    exact_direct = method.startswith("Enigma")
                    if exact_direct:
                        score = max(score, 0.98)
                        reason = "Direct settings-based decryption (exact)."
                    if statistical and not (is_flag or flag_shaped or recovered) \
                            and not clear_english(text) \
                            and not method.startswith("Enigma"):
                        score = min(score, 0.60)
                    # Statistical margin rows that only LOOK flag-shaped (no real
                    # dictionary gain over the input) must not outrank genuine
                    # evidence-based recoveries or the as-is floor.
                    if statistical and flag_shaped and not (
                            recovered or is_flag or strong_recovery or authoritative or strong_evidence):
                        score = min(score, 0.95)
                    # Final: unconfirmed recovered rows (not genuinely flag-shaped
                    # (full-buffer), English, or short technical verdicts) must
                    # not be lifted by flag-shape scoring.
                    _tech = (len(text) < 80 and sum(c.isprintable() for c in text) /
                             max(1, len(text)) > 0.95 and any(c in "=,;:" for c in text))
                    _fm = ctx.flag_regex.search(text)
                    _pok = bool(
                        _fm and _fm.group(0).isascii()
                        and _fm.group(0).isprintable()
                        and sum(c.isprintable() or c in "\r\n\t" for c in text)
                        / max(1, len(text)) >= 0.90
                        and "\ufffd" not in text)
                    if recovered and not statistical and not ((is_flagish(text) and ev_cover >= 0.9) or clear_english(text) or _tech or _pok):
                        score = min(score, 0.55)
                    subst_ok = False
                    if input_flag and not (is_flag or recovered):
                        # A transformed copy that is byte-identical to the input
                        # must never outrank the input as-is (compare letters only
                        # so trailing whitespace/newlines cannot hide an echo).
                        if "".join(ch for ch in text if ch.isalpha()) == \
                                "".join(ch for ch in blob.decode("utf-8", "replace") if ch.isalpha()):
                            score = min(score, 0.83)
                        elif flag_shaped:
                            # Only lift the candidate above the input-as-is when the
                            # claimed transform truly reproduces it (consistency).
                            method_base = method.split("(", 1)[0].lower().strip()
                            if _consistent_flag_recovery(
                                    method_base, raw_params,
                                    blob.decode("utf-8", "replace"), text):
                                score = max(score, 0.86)
                                subst_ok = method_base in (
                                    "atbash", "rot13", "rot47", "caesar", "affine",
                                    "vigenere-dictionary", "vigenere-wordlist",
                                    "gronsfeld", "beaufort", "porta")
                                # The strong lift above the as-is floor is only
                                # safe for fixed/keyless transforms and the
                                # dictionary/vigenere key words: their key
                                # space is bounded, so a consistent recovery is
                                # meaningful. Random-key classical ciphers
                                # (beaufort/gronsfeld/porta/affine) can be made
                                # consistent for *any* key, so they stay below
                                # the as-is 0.96 floor and never masquerade as
                                # the true decode.
                                strong_lift = method_base in (
                                    "atbash", "rot13", "rot47", "caesar",
                                    "vigenere-dictionary", "vigenere-wordlist")
                                if subst_ok and strong_lift:
                                    # Only deterministic fixed substitutions may
                                    # use the strong lift without body evidence;
                                    # every key-based transform must show a real
                                    # leet-body dictionary gain (a wrong key only
                                    # scrambles the body).
                                    fixed_mapping = method_base in (
                                        "atbash", "rot13", "rot47", "caesar")
                                    if fixed_mapping or ev_dgain > 0:
                                        delta = flag_plausibility(text) - input_plaus
                                        if delta > 0.02:
                                            score = max(score, 0.86 + 0.11 * min(1.0, delta / 0.4))
                            else:
                                score = min(score, 0.55)
                    record = {
                        "chain": " -> ".join(full_chain), "plaintext": text,
                        "confidence": round(max(0.0, min(1.0, score)), 4),
                        "is_flag": is_flag or flag_shaped, "_reason": reason, "_raw": out,
                        "_subst": subst_ok,
                        "_pdelta": flag_plausibility(text) - input_plaus if input_flag else 0.0,
                        "_english_ok": not (is_flag or flag_shaped) and clear_english(text),
                        "_trust": (3 if ((strong_recovery or is_flag or exact_direct or
                                          (recovered and ((is_flagish(text) and ev_cover >= 0.9) or clear_english(text) or _tech))) and not recovered_bad) else
                                   2 if (strong_evidence or
                                         (decoder_unknown and ev_cover >= 0.9)) else
                                   1 if (authoritative or method.split("(", 1)[0].lower().strip() in
                                         ("atbash", "rot13", "rot47", "caesar")) else
                                   0),
                    }
                    # Final safety: non-exact flag-shaped rows must never exceed .97
                    # (only known-prefix/exact recoveries and full-buffer
                    # transposition recoveries may).
                    if not (is_flag or recovered or strong_recovery) and record["confidence"] >= .98:
                        record["confidence"] = .97
                    # A regex match is authoritative, independent of score or
                    # prefix. Preserve the requested immediate flag exit -- but
                    # only for genuine flags. A low-confidence recovered row
                    # that merely LOOKS flag-shaped (e.g. a wrong-key XOR
                    # output) must not abort the search and discard the real
                    # recovery.
                    if is_flag and top > 0 and record["confidence"] >= 0.95:
                        return SearchResult([record], "FOUND", ctx.failures)
                    # Verified exact recovery bookkeeping + grace-gated early exit.
                    _full_shape = (is_flagish(text) or _flagout_ok) and ev_cover >= 0.9
                    _exact_like_decode = bool(
                        flag_shaped and _flagout_ok and ev_cover >= 0.9
                        and record["confidence"] >= 0.95
                        and base_method in ("single-byte xor", "repeating-key xor",
                                            "xor-short"))
                    _verified_exact = bool(
                        exact_direct or strong_recovery or _exact_like_decode or
                        (recovered and (_full_shape or clear_english(text) or _tech)) or
                        (is_flag and (match_text.lower().startswith(_KNOWN_PREFIXES) or _full_shape)))
                    if _verified_exact and not ctx.exact_found:
                        ctx.exact_found = True
                        ctx.exact_time = time.monotonic()
                        ctx.exact_chain = record["chain"]
                        if _exact_like_decode:
                            ctx.grace = 0.0
                    # Short text is retained for explicit LOW CONFIDENCE reporting.
                    if (score >= .62 or flag_shaped or (letters < 20 and score >= .28) or
                            (recovered and not recovered_bad) or
                            (relative_candidate and score >= .30) or
                            (reason.startswith("Partial solve:") and score >= .60)):
                        old = results.get(out)
                        if old is None or record["confidence"] > old["confidence"]:
                            results[out] = record
                    decoder = base_method in decoder_names
                    # Short classical outputs are statistically ambiguous. Keep
                    # them visible, but don't let them spawn combinatorial junk.
                    child_fp = fingerprint(out) if out and not decoder else {}
                    has_encoding = bool(child_fp.get("magic") or any(
                        score >= .75 for score in child_fp.get("prior_map", {}).values()
                    ))
                    prior_classical = any(
                        step.split("(", 1)[0].lower() not in decoder_names for step in chain
                    )
                    # Layered encodings are the high-value search graph. A
                    # classical candidate may continue only when it fingerprints
                    # as another encoding, avoiding combinatorial cipher chains.
                    # (Expansion is allowed even after a classical step if the
                    # output itself is an encoding — e.g. caesar -> base64 -> hex.)
                    should_expand = decoder or has_encoding
                    if (not recovered and depth < max_depth and out and len(out) <= 10_000_000
                            and should_expand and not ctx.exact_found):
                        digest = hashlib.sha256(out).digest()
                        if digest not in visited:
                            visited.add(digest)
                            serial += 1
                            priority = chain_prior * prior * (
                                .78 + .22 * score if decoder else max(.08, score)
                            )
                            # Deep decode chains (base64 -> bytes-literal -> hex
                            # -> ...) are high-value; give deeper nodes a modest
                            # multiplicative bump so they are not starved by
                            # high-prior single-step guesses.
                            if decoder or has_encoding:
                                priority *= 1.0 + 0.22 * depth
                            heapq.heappush(heap, (-priority, serial, out, full_chain,
                                                  priority, depth + 1))
                    if recovered:
                        # Exact attacks (RSA, cracking and explicit cribs) are
                        # terminal at this node, but don't stop other search paths.
                        break
            except (ValueError, OverflowError, UnicodeError, ArithmeticError):
                continue
            except _BUG_TYPES as e:
                # Unexpected exceptions (NameError, TypeError, ...) are bugs,
                # not malformed-input rejections: record them (and in strict
                # mode make the run fail after finishing).
                ctx.record_bug(item.name, e)
                continue
            except Exception:
                # A malformed input for one solver must not take down the run.
                continue
            finally:
                if ctx.progress_callback:
                    try:
                        ctx.progress_callback("")
                    except Exception:
                        pass
    if ctx.exact_found and ctx.pool is not None:
        try:
            ctx.pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
    ranked = sorted(results.values(),
                    key=lambda r: (-bool(r.get("_english_ok") and not r.get("is_flag")),
                                   -r["confidence"],
                                   -r.get("_trust", 0),
                                   # Prefer flag-shaped rows whose leet body is made
                                   # of real words (ties between equally-evidenced
                                   # candidates resolve to the more English body).
                                   (-leet_body_dict_fraction(r["plaintext"])
                                    if r.get("is_flag") else 0.0),
                                   # but a flag body is not English: a higher ec there
                                   # just means more noise/leet-lookalike contamination.
                                   (english_confidence(r["plaintext"])
                                    if r.get("is_flag") else -english_confidence(r["plaintext"])),
                                   -bool(r.get("_subst")), -r.get("_pdelta", 0.0),
                                   r["chain"]))[:max(0, top)]
    if ranked:
        status = "FOUND"
    elif ctx.expired():
        status = "TIMEOUT"
    elif ctx.failures:
        status = "SOLVER_FAILED"
    else:
        try:
            text = data.decode("ascii", "ignore")
        except Exception:
            text = ""
        status = "TOO_SHORT" if sum(c.isalpha() for c in text) < 20 else "NOT_FOUND"
    return SearchResult(ranked, status, ctx.failures)
