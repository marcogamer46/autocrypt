"""Phase 4 tests: Vigenère crack + user-supplied key (--key).

Covers:
  - Statistical crack (Kasiski/IoC key length + per-column Caesar) recovers
    a flag from Vigenère ciphertext.
  - The user-supplied key path (--key) decrypts directly with high confidence.
  - The CLI --key flag works end-to-end.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"

from autocrypt.cli import solve_data  # noqa: E402

PLAIN = ("the academy flag is academy{vigenere_crack_works} "
         "gather your forces and march onward into the night")
KEY = "lemon"


def _vigenere(plain, key, mode="vigenere"):
    ks = [ord(c) - 97 for c in key.lower()]
    out = []
    j = 0
    for ch in plain:
        if ch.isalpha() and ch.lower() in "abcdefghijklmnopqrstuvwxyz":
            x = ord(ch.lower()) - 97
            k = ks[j % len(ks)]
            if mode == "vigenere":
                p = (x + k) % 26
            elif mode == "beaufort":
                p = (k - x) % 26
            else:  # variant-beaufort
                p = (x - k) % 26
            out.append(chr(p + (65 if ch.isupper() else 97)))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


FLAG = "academy{vigenere_crack_works}"


def _has_flag(res, flag=FLAG):
    return any(flag in r.get("plaintext", "").lower() for r in res)


def test_crack_recovers_flag():
    ct = _vigenere(PLAIN, KEY).encode()
    _, res, _ = solve_data(ct, timeout=15, top=12, jobs=1)
    assert _has_flag(res), [r.get("plaintext", "")[:60] for r in res]
    chains = " ".join(r.get("chain", "") for r in res)
    # any statistical vigenere route is a correct recovery
    assert any("vigenere" in c for c in chains.split())


def test_user_key_decrypts():
    ct = _vigenere(PLAIN, KEY).encode()
    _, res, _ = solve_data(ct, timeout=10, top=12, jobs=1, key=KEY)
    assert _has_flag(res), [r.get("plaintext", "")[:60] for r in res]
    chains = " ".join(r.get("chain", "") for r in res)
    assert "vigenere(key)" in chains


def test_user_key_flag_shown_high_conf():
    flag = "academy{user_key_ok}"
    ct = _vigenere(flag, KEY).encode()
    _, res, _ = solve_data(ct, timeout=10, top=12, jobs=1, key=KEY)
    assert _has_flag(res, flag), [r.get("plaintext", "")[:60] for r in res]
    # the flag-shaped recovery claims high confidence
    frows = [r for r in res if flag in r.get("plaintext", "").lower()]
    assert frows and frows[0]["confidence"] >= 0.9


def test_cli_key_flag_end_to_end():
    ct = _vigenere(PLAIN, KEY)
    p = subprocess.run(
        [sys.executable, "-m", "autocrypt", "--key", KEY, "--json"],
        input=ct.encode(), capture_output=True)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    import json
    payload = json.loads(p.stdout.decode("utf-8"))
    texts = " ".join(r.get("plaintext", "") for r in payload["results"]).lower()
    assert FLAG in texts


def main():
    test_crack_recovers_flag()
    test_user_key_decrypts()
    test_user_key_flag_shown_high_conf()
    test_cli_key_flag_end_to_end()
    print("VIGENERE-CRACK: ALL OK")


if __name__ == "__main__":
    main()
