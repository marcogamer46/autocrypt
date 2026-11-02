"""Extra encodings and a couple of niche classical/esoteric decoders.

Kept separate from solvers.py so the core registry stays readable; each
function here registers itself with the same @solver decorator and plugs
into the existing fingerprint -> search pipeline automatically.
"""
from __future__ import annotations

import binascii
import io
import re
import string
import zipfile

from core import solver
from scoring import assess


def _prior(fp, *names, default=0.0):
    return max((fp.get("prior_map", {}).get(n, 0.0) for n in names), default=default)


def _emit(ctx, plain, method, params=None):
    params = params or {}
    score, _ = assess(plain)
    yield plain, method, params, score


# ---------------------------------------------------------------- base45 ---
_B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_INDEX = {c: i for i, c in enumerate(_B45_ALPHABET)}


def _base45_decode(text: str) -> bytes:
    # Space is a real base45 symbol (alphabet index 36), not whitespace to
    # discard, so every character here must already be in the alphabet.
    chars = list(text)
    out = bytearray()
    i = 0
    while i < len(chars):
        group = chars[i:i + 3]
        if len(group) == 3:
            n = _B45_INDEX[group[0]] + _B45_INDEX[group[1]] * 45 + _B45_INDEX[group[2]] * 45 * 45
            if n > 0xFFFF:
                raise ValueError("base45 group out of range")
            out += n.to_bytes(2, "big")
        elif len(group) == 2:
            n = _B45_INDEX[group[0]] + _B45_INDEX[group[1]] * 45
            if n > 0xFF:
                raise ValueError("base45 trailing group out of range")
            out.append(n)
        else:
            raise ValueError("base45 length must not leave a single character")
        i += 3
    return bytes(out)


@solver("base45", lambda fp: .55 if fp["charset"] == "ascii-text" and 4 <= fp["length"] <= 20_000
        and fp.get("_text", "").strip() and set(fp["_text"].strip()) <= set(_B45_ALPHABET)
        else 0.0)
def solve_base45(data, ctx):
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return
    if not text or any(c not in _B45_INDEX for c in text):
        return
    try:
        out = _base45_decode(text)
    except ValueError:
        return
    if out:
        yield from _emit(ctx, out, "base45")


# ---------------------------------------------------------------- base36 ---
@solver("base36", lambda fp: .25 if fp["charset"] == "ascii-text"
        and re.fullmatch(r"[0-9A-Za-z]+", fp.get("_text", "").strip() or "x ")
        and 6 <= fp["length"] <= 80 else 0.0)
def solve_base36(data, ctx):
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return
    if not text or not re.fullmatch(r"[0-9A-Za-z]+", text) or text.isdigit():
        return
    try:
        n = int(text, 36)
    except ValueError:
        return
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    if out:
        yield from _emit(ctx, out, "base36")


# -------------------------------------------------------------- uuencode ---
@solver("uuencode", lambda fp: .5 if b"begin " in fp.get("_head", b"") and fp["charset"] == "ascii-text" else 0.0)
def solve_uuencode(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("begin ")), None)
    if start is None:
        return
    out = bytearray()
    for line in lines[start + 1:]:
        if line.strip() in ("end", "`"):
            break
        try:
            out += binascii.a2b_uu(line + "\n" if not line.endswith("\n") else line)
        except (binascii.Error, ValueError):
            continue
    if out:
        yield from _emit(ctx, bytes(out), "uuencode")


# --------------------------------------------------------- NATO phonetic ---
_NATO = {
    "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d", "echo": "e",
    "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i", "juliet": "j",
    "juliett": "j", "kilo": "k", "lima": "l", "mike": "m", "november": "n",
    "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r", "sierra": "s",
    "tango": "t", "uniform": "u", "victor": "v", "whiskey": "w", "whisky": "w",
    "x-ray": "x", "xray": "x", "yankee": "y", "zulu": "z",
}


@solver("nato-phonetic", lambda fp: .4 if fp["charset"] == "ascii-text" and fp["length"] >= 10 else 0.0)
def solve_nato(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    tokens = re.findall(r"[A-Za-z-]+", text)
    if len(tokens) < 5:
        return
    hits = sum(1 for t in tokens if t.lower() in _NATO)
    if hits / len(tokens) < .7:
        return
    out = "".join(_NATO.get(t.lower(), "") for t in tokens)
    if out:
        yield from _emit(ctx, out, "NATO phonetic")


# --------------------------------------------------------------- brainfuck -
def _is_brainfuck(text):
    cmds = set("><+-.,[]")
    meaningful = [c for c in text if not c.isspace()]
    if len(meaningful) < 8:
        return False
    hits = sum(1 for c in meaningful if c in cmds)
    return hits / len(meaningful) >= .85 and "." in meaningful and ("[" in meaningful or len(meaningful) < 40)


@solver("brainfuck", lambda fp: .5 if fp["charset"] == "ascii-text"
        and _is_brainfuck(fp.get("_text", "")) else 0.0)
def solve_brainfuck(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    if not _is_brainfuck(text):
        return
    code = [c for c in text if c in "><+-.,[]"]
    jumps = {}
    stack = []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return
            j = stack.pop()
            jumps[i], jumps[j] = j, i
    if stack:
        return
    tape = bytearray(30_000)
    ptr = pc = 0
    out = bytearray()
    steps = 0
    while pc < len(code) and steps < 2_000_000 and len(out) < 20_000:
        c = code[pc]
        if c == ">":
            ptr = (ptr + 1) % len(tape)
        elif c == "<":
            ptr = (ptr - 1) % len(tape)
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == ".":
            out.append(tape[ptr])
        elif c == ",":
            pass
        elif c == "[" and tape[ptr] == 0:
            pc = jumps[pc]
        elif c == "]" and tape[ptr] != 0:
            pc = jumps[pc]
        pc += 1
        steps += 1
    if out:
        yield from _emit(ctx, bytes(out), "brainfuck")


# ----------------------------------------------------------- zip archive ---
@solver("zip-archive", lambda fp: .9 if fp.get("filetype") == "ZIP archive" else 0.0)
def solve_zip(data, ctx):
    if ctx.depth > 0:
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return
    names = zf.namelist()
    shown = ", ".join(names[:10]) + (", ..." if len(names) > 10 else "")
    ctx.findings.append(f"ZIP archive with {len(names)} entr{'y' if len(names) == 1 else 'ies'}: {shown}")
    if any(info.flag_bits & 0x1 for info in zf.infolist()):
        ctx.findings.append("One or more ZIP entries are password-protected "
                             "(not auto-cracked; supply a password separately).")
    for info in zf.infolist()[:8]:
        if info.flag_bits & 0x1 or info.file_size > 3_000_000 or info.is_dir():
            continue
        try:
            content = zf.read(info.filename)
        except (RuntimeError, zipfile.BadZipFile, OSError):
            continue
        if content:
            yield content, "zip entry", {"name": info.filename}, .3
