"""Phase 2 + Phase 3 tests: scoring profiles (--profile) and known-key mode.

Covers:
  - get_assessor returns the right scorer per profile name, defaulting to flag.
  - token_score ranks token/code-shaped output (JWT/UUID/hex) structurally.
  - readable_score ranks printable/clean text without English gating.
  - none_score gives a neutral score.
  - known-key mode: solve_known_key recovers Vigenère, repeating-XOR and RC4
    (including hash-derived keys) from ctx.key, and yields nothing for a wrong key.

Run:  PYTHONPATH=. .venv/Scripts/python.exe test_profiles_and_knownkey.py
"""
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _ctx(key="", profile="flag"):
    from autocrypt.core import Context
    from autocrypt.scoring import get_assessor
    return Context(
        deadline=time.monotonic() + 15,
        flag_regex=re.compile(r"\w{1,40}\{.*?\}", re.DOTALL),
        key=key, assess=get_assessor(profile), profile=profile)


# ---------------------------------------------------------------- profiles ----

def test_get_assessor_profiles():
    from autocrypt.scoring import get_assessor, assess, token_score, readable_score, none_score
    assert get_assessor(None) is assess
    assert get_assessor("") is assess
    assert get_assessor("FLAG") is assess
    assert get_assessor("token") is token_score
    assert get_assessor("readable") is readable_score
    assert get_assessor("none") is none_score
    print("OK  get_assessor profile resolution")


def test_token_score_ranks_structure():
    from autocrypt.scoring import token_score
    uuid = b"550e8400-e29b-41d4-a716-446655440000"
    jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
    hexblob = b"deadbeefdeadbeefdeadbeefdeadbeef"
    garbage = b"\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
    assert token_score(uuid)[0] >= 0.6
    assert token_score(hexblob)[0] >= 0.55
    # clean structure ranks well above high-entropy junk; empty scores 0
    assert token_score(uuid)[0] > token_score(garbage)[0] + 0.25
    assert token_score(b"")[0] == 0.0
    print("OK  token_score ranks structure")


def test_readable_score_english_independent():
    from autocrypt.scoring import readable_score
    label_text = b"name: alpha\nrole: admin\nid: 42"
    assert readable_score(label_text)[0] >= 0.8
    assert readable_score(b"\xff\x00\x01\x02\x03")[0] <= 0.3
    print("OK  readable_score")


def test_none_score_neutral():
    from autocrypt.scoring import none_score
    s = none_score(b"some printable string here")
    assert 0.5 <= s[0] <= 1.0
    print("OK  none_score neutral")


# -------------------------------------------------------------- known-key ----

def _vigenere_enc(text, key):
    out, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[j % len(key)]) - ord("A")
            out.append(chr(base + (ord(ch) - base + k) % 26))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def test_knownkey_vigenere_recovers():
    from autocrypt.solvers_pack7 import solve_known_key
    ct = _vigenere_enc("the quick brown fox jumps over the lazy dog", "SECRET")
    res = list(solve_known_key(ct.encode(), _ctx(key="secret")))
    pts = [r[0] for r in res]
    assert any("the quick brown fox jumps over the lazy dog" in p for p in pts), pts
    # wrong key yields nothing
    res_bad = list(solve_known_key(ct.encode(), _ctx(key="wrongkey")))
    assert not any("the quick brown fox" in r[0] for r in res_bad)
    print("OK  known-key Vigenère recovers; wrong key yields nothing")


def test_knownkey_vigenere_flagshape():
    from autocrypt.solvers_pack7 import solve_known_key
    ct = _vigenere_enc("academy{known_key_mode_works}", "SECRET")
    res = list(solve_known_key(ct.encode(), _ctx(key="secret")))
    assert any(r[0] == "academy{known_key_mode_works}" and r[3] >= 0.95 for r in res)
    print("OK  known-key flag-shaped Vigenère")


def test_knownkey_repeating_xor():
    from autocrypt.solvers_pack7 import solve_known_key
    pt = b"congratulations you solved the repeating xor challenge"
    key = b"secret"
    ct = bytes(pt[i] ^ key[i % len(key)] for i in range(len(pt)))
    res = list(solve_known_key(ct, _ctx(key="secret")))
    assert any(b"congratulations you solved" in r[0].encode() for r in res)
    print("OK  known-key repeating-XOR")


def test_knownkey_rc4_hashed_key():
    from autocrypt.solvers_pack7 import solve_known_key, _rc4
    import hashlib
    derived = hashlib.sha256(b"fizzbuzz").digest()
    ct = _rc4(derived, b"RC4 challenge plaintext with sha256 derived key")
    res = list(solve_known_key(ct, _ctx(key="fizzbuzz")))
    assert any("RC4 challenge plaintext" in r[0] for r in res), res
    print("OK  known-key RC4 with sha256-derived key")


def test_knownkey_candidates_dedupe():
    from autocrypt.solvers_pack7 import _known_key_candidates
    c = _known_key_candidates("secret")
    labels = [l for l, _ in c]
    assert "raw" in labels and "md5-raw" in labels and "sha256-hex" in labels
    # no duplicate key-bytes forms (raw vs hex-collision deduped)
    keys = [k for _, k in c]
    assert len(keys) == len(set(keys))
    print("OK  known-key candidate derivations")


def main():
    test_get_assessor_profiles()
    test_token_score_ranks_structure()
    test_readable_score_english_independent()
    test_none_score_neutral()
    test_knownkey_vigenere_recovers()
    test_knownkey_vigenere_flagshape()
    test_knownkey_repeating_xor()
    test_knownkey_rc4_hashed_key()
    test_knownkey_candidates_dedupe()
    print("PROFILES_KNOWNKEY: ALL OK")


if __name__ == "__main__":
    main()
