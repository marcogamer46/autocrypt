#!/usr/bin/env python3
"""Regression tests for the playfair, hill-2x2 solvers and the watcher
classifier.

Run:  PYTHONPATH=. .venv/Scripts/python.exe test_playfair_hill_watcher.py
"""
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from autocrypt.core import Context
from autocrypt.solvers import _playfair_decrypt, _playfair_worker, solve_playfair
from autocrypt.solvers_more import _A, solve_hill2
import autocrypt.watcher as watcher

_FLAG_RE = re.compile(r"\w{1,40}\{.*?\}")


def _ctx(t=20.0):
    return Context(deadline=time.monotonic() + t, flag_regex=_FLAG_RE)


# Standard 5x5 Playfair square (J folded into I).
SQUARE = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def _playfair_encrypt(text, square):
    """Inverse of _playfair_decrypt: same-row -> right, same-col -> down."""
    clean = [c for c in text.upper() if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    clean = ["I" if c == "J" else c for c in clean]
    if len(clean) % 2:
        clean.append("X")
    pos = {c: divmod(i, 5) for i, c in enumerate(square)}
    out = []
    for a, b in zip(clean[::2], clean[1::2]):
        r1, c1 = pos[a]; r2, c2 = pos[b]
        if r1 == r2:
            out.extend((square[r1 * 5 + (c1 + 1) % 5],
                        square[r2 * 5 + (c2 + 1) % 5]))
        elif c1 == c2:
            out.extend((square[((r1 + 1) % 5) * 5 + c1],
                        square[((r2 + 1) % 5) * 5 + c2]))
        else:
            out.extend((square[r1 * 5 + c2], square[r2 * 5 + c1]))
    return "".join(out)


def test_playfair_decrypt_known_vector():
    """Deterministic check of the decrypt primitive on a fixed square/input.
    Standard square:
      A B C D E / F G H I K / L M N O P / Q R S T U / V W X Y Z
    Decrypt: same row -> left shift; same column -> up shift; else rectangle.
    """
    # AB: A(0,0) B(0,1) same row -> left: A->E(0,4), B->A(0,0)
    assert _playfair_decrypt("AB", SQUARE) == "EA", _playfair_decrypt("AB", SQUARE)
    # AC: A(0,0) C(0,2) same row -> left: A->E(0,4), C->B(0,1)
    assert _playfair_decrypt("AC", SQUARE) == "EB", _playfair_decrypt("AC", SQUARE)
    # AF: A(0,0) F(1,0) same col -> up: A->V(4,0), F->A(0,0)
    assert _playfair_decrypt("AF", SQUARE) == "VA", _playfair_decrypt("AF", SQUARE)
    # BF: B(0,1) F(1,0) rectangle -> swap cols: B->A(0,0), F->G(1,1)
    assert _playfair_decrypt("BF", SQUARE) == "AG", _playfair_decrypt("BF", SQUARE)
    print("OK  playfair decrypt known vectors")


def test_playfair_roundtrip():
    """Encrypt with the inverse then decrypt recovers the plaintext.
    Use a J-free, even-length plaintext (J folds into I; odd length pads X)."""
    pt = "thequickbrownfoxrumpsverthelazydog"  # 32 letters, even, no J
    ct = _playfair_encrypt(pt, SQUARE)
    assert _playfair_decrypt(ct, SQUARE).lower() == pt.lower()
    print("OK  playfair round-trip (encrypt->decrypt)")


def test_playfair_solver_runs():
    """The playfair solver is a stochastic hillclimber; it must not crash,
    must yield at least one printable candidate, and must not hardcode a flag.
    Exact recovery is not guaranteed (heuristic), so we assert on the
    invariant: non-empty, printable, ASCII output."""
    pt = "thequickbrownfoxjumpsoverthelazydog"
    ct = _playfair_encrypt(pt, SQUARE)
    ctx = _ctx()
    out = None
    for plain, method, params, score in solve_playfair(ct.encode("ascii"), ctx):
        out = plain
        break
    assert out is not None, "playfair solver yielded nothing"
    rec = (out.decode("ascii", "replace") if isinstance(out, bytes) else out)
    assert rec.isprintable(), "playfair candidate is not printable"
    assert all(32 <= ord(ch) < 127 for ch in rec), "playfair candidate not ASCII"
    assert "academy{" not in rec, "playfair solver returned a hardcoded flag"
    print(f"OK  playfair solver runs and yields printable candidate ({rec[:20]!r}...)")


def test_hill2_solver_recovers():
    """Hill 2x2 full-enumeration solver recovers a known-key ciphertext.

    The solver's greedy prefilter ranks keys on the first 6 pairs and keeps
    only the top 12, so we use a plaintext whose first quadgraphs are strong
    enough that the true key is ranked #0 there (verified: rank 0)."""
    # Key [[3,5],[2,7]]; det = 3*7-5*2 = 11 (invertible mod 26).
    key = (3, 5, 2, 7)
    pt = "wheninthecourseofhumanevents"  # 28 letters, even
    L = [ord(ch) - 65 for ch in pt.upper() if ch.isalpha()]
    pairs = [(L[i], L[i + 1]) for i in range(0, len(L) - 1, 2)]
    a, b, c, d = key
    ct = "".join(
        _A[(a * x + b * y) % 26] + _A[(c * x + d * y) % 26] for x, y in pairs)
    ctx = _ctx(40.0)
    got = []
    for plain, method, params, score in solve_hill2(ct.encode("ascii"), ctx):
        got.append(plain.decode("ascii", "replace").lower())
        if len(got) >= 5:
            break
    assert got, "hill-2x2 solver yielded nothing"
    assert got[0] == pt.lower(), f"hill top-1 {got[0]!r} != {pt!r}"
    print(f"OK  hill-2x2 solver recovers (top-1 = {got[0]!r})")


def test_watcher_classify():
    assert watcher.classify("") == "other"
    assert watcher.classify("all good") == "other"
    assert watcher.classify("HTTP 429 rate limit exceeded") == "api"
    assert watcher.classify("upstream request failed") == "api"
    assert watcher.classify("the session was flagged") == "flagged"
    assert watcher.classify("moderation triggered") == "api"
    assert watcher.classify("connection reset") == "api"
    print("OK  watcher classify api/flagged/other")


def main():
    test_playfair_decrypt_known_vector()
    test_playfair_roundtrip()
    test_playfair_solver_runs()
    test_hill2_solver_recovers()
    test_watcher_classify()
    print("PLAYFAIR_HILL_WATCHER: ALL OK")


if __name__ == "__main__":
    main()
