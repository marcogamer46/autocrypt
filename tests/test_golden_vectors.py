"""Golden-vector regression battery.

For every solver family, generate a ciphertext from a known plaintext
(ending in a flag token) and assert the FULL orchestration
(autocrypt.solve_data: fingerprint -> scheduling -> scoring -> recursion)
recovers the plaintext. This is a safety net for architecture changes:
scoring, recursion, scheduling, and dedupe must not silently lose a family.

Run:  PYTHONPATH=. .venv/Scripts/python.exe tests/test_golden_vectors.py
"""

import base64
import binascii
import os
import re
import string
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import autocrypt  # noqa: E402

_FLAG = "flag{GoldenVecT0r}"
_PLAIN = "the quick brown fox jumps over the lazy dog " + _FLAG
_LETTERS_ONLY = "welcome to the golden regression suite"
_WANT_WORD = "goldenregressionsuite"


def _norm(s):
    return re.sub(r"[^A-Za-z0-9]", "", s).lower()


def _recovers(data, want=_FLAG, timeout=6.0):
    fp, res, ctx = autocrypt.solve_data(
        data, flag_format=r"\w{1,40}\{.*?\}", timeout=timeout)
    texts = [_norm(r["plaintext"]) for r in res]
    return any(_norm(want) in t for t in texts)


# ---------------------------------------------------------------------------
# encoders
# ---------------------------------------------------------------------------
def _enc_caesar(s, k):
    out = []
    for ch in s:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + k) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _enc_atbash(s):
    return "".join(
        chr(ord("A") + 25 - (ord(ch) - ord("A"))) if ch.isupper()
        else chr(ord("a") + 25 - (ord(ch) - ord("a"))) if ch.islower()
        else ch for ch in s)


def _enc_affine(s, a=5, b=8):
    out = []
    for ch in s:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((a * (ord(ch) - base) + b) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _enc_vigenere(s, key="LEMON"):
    out = []
    ki = 0
    for ch in s:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[ki % len(key)]) - ord("A")
            out.append(chr((ord(ch) - base + k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _enc_beaufort(s, key="LEMON"):
    out = []
    ki = 0
    for ch in s:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[ki % len(key)]) - ord("A")
            p = ord(ch) - base
            out.append(chr((k - p) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _enc_railfence(s, rails=2):
    rows = [""] * rails
    r, dr = 0, 1
    for ch in s:
        rows[r] += ch
        if rails > 1:
            r += dr
            if r == 0 or r == rails - 1:
                dr = -dr
    return "".join(rows)


def _enc_columnar(s, width=5):
    rows = [s[i:i + width] for i in range(0, len(s), width)]
    height = len(rows)
    return "".join(rows[r][c] for c in range(width) for r in range(height)
                   if c < len(rows[r]))


def _enc_scytale(s, width=5):
    # read columns top-to-bottom over the row-major grid
    rows = [s[i:i + width] for i in range(0, len(s), width)]
    return "".join(rows[r][c] for c in range(width) for r in range(len(rows))
                   if c < len(rows[r]))


_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.",
}


def _enc_morse(s):
    words = []
    for w in s.split():
        words.append(" ".join(_MORSE.get(ch.upper(), "") for ch in w if ch.isalnum()))
    return " / ".join(words)


def _enc_binary(s):
    return " ".join(f"{b:08b}" for b in s.encode())


def _enc_octal(s):
    return " ".join(f"{b:03o}" for b in s.encode())


def _enc_decimal(s):
    return " ".join(str(b) for b in s.encode())


def _enc_hex(s):
    return s.encode().hex()


def _enc_base64(s):
    return base64.b64encode(s.encode()).decode()


def _enc_base32(s):
    return base64.b32encode(s.encode()).decode()


def _enc_url(s):
    return urllib.parse.quote(s, safe="")


def _enc_qp(s):
    import quopri
    return quopri.encodestring(s.encode()).decode()


def _enc_a1z26(s):
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(str(ord(ch.upper()) - ord("A") + 1))
    return "-".join(out)


def _enc_xor_single(s, k=0x42):
    return bytes(b ^ k for b in s.encode())


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
def test_golden_hex():
    assert _recovers(_enc_hex(_PLAIN).encode())


def test_golden_base64():
    assert _recovers(_enc_base64(_PLAIN).encode())


def test_golden_base32():
    assert _recovers(_enc_base32(_PLAIN).encode())


def test_golden_binary():
    assert _recovers(_enc_binary(_PLAIN).encode())


def test_golden_octal():
    assert _recovers(_enc_octal(_PLAIN).encode())


def test_golden_decimal():
    assert _recovers(_enc_decimal(_PLAIN).encode())


def test_golden_url():
    assert _recovers(_enc_url(_PLAIN).encode())


def test_golden_qp():
    assert _recovers(_enc_qp(_PLAIN).encode())


def test_golden_rot13():
    assert _recovers(_enc_caesar(_PLAIN, 13).encode())


def test_golden_rot47():
    tbl = "".join(chr(33 + ((ord(c) - 33 + 47) % 94))
                   if 33 <= ord(c) <= 126 else c for c in _PLAIN)
    assert _recovers(tbl.encode())


def test_golden_atbash():
    assert _recovers(_enc_atbash(_PLAIN).encode())


def test_golden_caesar():
    assert _recovers(_enc_caesar(_PLAIN, 7).encode())


def test_golden_affine():
    assert _recovers(_enc_affine(_PLAIN).encode())


def test_golden_vigenere():
    assert _recovers(_enc_vigenere(_PLAIN).encode())


def test_golden_beaufort():
    assert _recovers(_enc_beaufort(_PLAIN).encode())


def test_golden_railfence():
    assert _recovers(_enc_railfence(_PLAIN, 2).encode())


def test_golden_columnar():
    assert _recovers(_enc_columnar(_PLAIN).encode())


def test_golden_scytale():
    assert _recovers(_enc_scytale(_PLAIN, 5).encode())


def test_golden_morse():
    assert _recovers(_enc_morse(_LETTERS_ONLY).encode(), _WANT_WORD)


def test_golden_a1z26():
    assert _recovers(_enc_a1z26(_LETTERS_ONLY).encode(), _WANT_WORD)


def test_golden_xor_single():
    assert _recovers(_enc_xor_single(_PLAIN))


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_golden_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError:
            failed += 1
            print(f"FAIL {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} golden vectors recovered")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
