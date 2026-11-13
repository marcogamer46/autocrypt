"""Regression tests for the morse and binary solver enhancements.

Morse: punctuation, `|` letter separator, lenient unknown-token handling.
Binary: space-separated tokens with stripped leading zeros recover per byte.

These assert at the solver level (the emitted (plaintext, method) tuples),
which is stable regardless of orchestration ranking. One integration check
(the live UI input) confirms the decode also surfaces through solve_data.

Run:  PYTHONPATH=. .venv/Scripts/python.exe tests/test_morse_binary.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from autocrypt.solvers import solve_binary, solve_morse  # noqa: E402

import autocrypt  # noqa: E402


def _decodes(fn, data):
    return fn(data, None)


def _plain(fn, data):
    return [out[0] for out in fn(data, None)]


def _methods(fn, data):
    return [out[1] for out in fn(data, None)]


def test_morse_punctuation():
    out = list(_decodes(solve_morse, b"- . ... - --..-- / --- -.- .-.-.-"))
    assert out and out[0][0] == "TEST, OK." and out[0][1] == "morse"


def test_morse_pipe_separator():
    # '|' is used as a letter separator in place of space.
    out = list(_decodes(solve_morse, b"....|..|-..|.-.."))  # H I D L
    assert out and out[0][0] == "HIDL"


def test_morse_lenient_unknown_token():
    # A stray unknown token must not abort the whole decode.
    out = list(_decodes(solve_morse, b".... . .-.. .-.. --- xxxxx"))
    assert out and out[0][0] == "HELLO"


def test_binary_padded_tokens():
    # Leading-zero stripped bytes (space-separated) recover per token.
    out = list(_decodes(solve_binary, b"1001000 1101001"))
    assert any(p == b"Hi" and m == "binary (padded)" for p, m, *_ in out)


def test_binary_plain_stream():
    out = list(_decodes(solve_binary, b"011110010110010101110011"))  # "yes"
    assert any(p == b"yes" for p, m, *_ in out)


def test_morse_live_ui_input():
    # Exact input pasted from a live UI session: the real morse plaintext must
    # be recoverable end-to-end through solve_data.
    data = b"-.. --- - ... .- -. -.. -.. .- ... .... . ..."
    fp, res, ctx = autocrypt.solve_data(
        data, flag_format=r"\w{1,40}\{.*?\}", timeout=6.0)
    texts = [re.sub(r"[^A-Za-z0-9]", "", r["plaintext"]).lower() for r in res]
    assert any("dotsanddashes" in t for t in texts)


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print("MORSE_BINARY:", "ALL OK" if failed == 0 else f"{failed} FAILED")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
