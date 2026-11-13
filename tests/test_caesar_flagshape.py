"""Regression tests for the Caesar solver's flag-shaped recovery.

CTF Caesar bodies are often leet/random-looking, so they rank mid-list in the
generic English ranking; a shift that reveals a recognized flag wrapper with a
plausible body should surface as a confident candidate.

Run:  PYTHONPATH=. .venv/Scripts/python.exe tests/test_caesar_flagshape.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import autocrypt  # noqa: E402


def _rot(s, k):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


_FLAGS = [
    "academy{pwn_leet_caesar}",
    "flag{cae_salter_v2}",
    "picoCTF{caesar_is_basic_128}",
    "htb{bruteforce_me_plz}",
]


def _recovers_flag(data, want):
    fp, res, ctx = autocrypt.solve_data(
        data, flag_format=r"\w{1,40}\{.*?\}", timeout=6.0)
    texts = [re.sub(r"[^A-Za-z0-9]", "", r["plaintext"]).lower() for r in res]
    wantn = re.sub(r"[^A-Za-z0-9]", "", want).lower()
    return any(wantn in t for t in texts)


def test_caesar_flag_recovery():
    for f in _FLAGS:
        k = 7 + (sum(ord(c) for c in f) % 19)
        assert _recovers_flag(_rot(f, k).encode(), f), f"shift k={k} for {f}"


def test_caesar_nonenglish_latin_body_recovers():
    # A Caesar-encrypted flag whose body is a well-known Latin phrase
    # ("et tu, Brute"): tokens are real words but fall outside the small
    # _COMMON set, so recovery must use the fuller wordlist. The encrypted
    # prefix is not a known flag prefix either, so the generic shell scan must
    # surface it.
    data = b"jzww{la_ab_iybal}"
    fp, res, ctx = autocrypt.solve_data(
        data, flag_format=r"\w{1,40}\{.*?\}", timeout=6.0)
    assert res, "expected at least one candidate"
    assert res[0]["plaintext"] == "cspp{et_tu_brute}", \
        [r["plaintext"] for r in res[:5]]


def test_caesar_english_still_works():
    # Classic English text must still recover (regression guard for the early
    # flag-return path).
    plain = "the quick brown fox jumps over the lazy dog"
    data = _rot(plain, 13).encode()
    fp, res, ctx = autocrypt.solve_data(
        data, flag_format=r"\w{1,40}\{.*?\}", timeout=6.0)
    texts = [re.sub(r"[^A-Za-z0-9]", "", r["plaintext"]).lower() for r in res]
    assert any("thequickbrownfoxjumpsoverthelazydog" in t for t in texts)


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
    print("CAESAR_FLAGSHAPE:", "ALL OK" if failed == 0 else f"{failed} FAILED")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
