"""Phase 6 tests: extras — UTF-16/UTF-32 text, bzip2 decompression, and using
the user-supplied key (--key) for XOR decryption.

Covers:
  - UTF-16LE (BOM) text recovers an embedded flag.
  - UTF-16BE text recovers an embedded flag.
  - bzip2-compressed bytes decompress to a flag.
  - `--key` decrypts single-byte XOR (hex key).
  - `--key` decrypts repeating-key XOR (ASCII key).
  - A wrong user key does not crash; auto-crack still runs.
"""
import bz2
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"

from autocrypt.cli import solve_data  # noqa: E402


def _solve(data, **kw):
    _, res, _ = solve_data(data, timeout=12, top=12, jobs=1, **kw)
    return res


def _has_flag(res, flag):
    flag = flag.lower()
    return any(flag in r.get("plaintext", "").lower() for r in res)


def test_utf16le_recovers_flag():
    flag = "academy{utf16le_ok}"
    data = flag.encode("utf-16")  # BOM + LE on little-endian hosts
    res = _solve(data)
    assert _has_flag(res, flag), [r.get("plaintext", "")[:40] for r in res]


def test_utf16be_recovers_flag():
    flag = "academy{utf16be_ok}"
    data = flag.encode("utf-16-be")
    res = _solve(data)
    assert _has_flag(res, flag), [r.get("plaintext", "")[:40] for r in res]


def test_bzip2_decompresses_flag():
    flag = "academy{bz2_ok}"
    data = bz2.compress(flag.encode())
    res = _solve(data)
    assert _has_flag(res, flag), [r.get("plaintext", "")[:40] for r in res]


def test_key_single_byte_xor():
    flag = "academy{xor1_key_ok}"
    ct = bytes(b ^ 0x5A for b in flag.encode())
    res = _solve(ct, key="5a")
    assert _has_flag(res, flag), [r.get("plaintext", "")[:40] for r in res]


def test_key_repeating_xor():
    flag = "academy{xorN_key_ok}"
    key = b"k3y"
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag.encode()))
    res = _solve(ct, key="k3y")
    assert _has_flag(res, flag), [r.get("plaintext", "")[:40] for r in res]


def test_wrong_key_does_not_crash():
    flag = "academy{auto_crack_still}"
    # single-byte XOR with a wrong user key: no crash, auto-crack still recovers
    plain = f"The academy flag is {flag} and the message continues on."
    ct = bytes(b ^ 0x2B for b in plain.encode())
    res = _solve(ct, key="deadbeef")
    assert _has_flag(res, flag), [r.get("plaintext", "")[:40] for r in res]


def test_cli_key_flag_for_xor():
    flag = "academy{cli_xor_key}"
    key = b"lemon"
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag.encode()))
    p = subprocess.run(
        [sys.executable, "-m", "autocrypt", "--key", "lemon", "--json"],
        input=ct, capture_output=True)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    import json
    payload = json.loads(p.stdout.decode("utf-8"))
    texts = " ".join(r.get("plaintext", "") for r in payload["results"]).lower()
    assert flag in texts


def main():
    test_utf16le_recovers_flag()
    test_utf16be_recovers_flag()
    test_bzip2_decompresses_flag()
    test_key_single_byte_xor()
    test_key_repeating_xor()
    test_wrong_key_does_not_crash()
    test_cli_key_flag_for_xor()
    print("EXTRAS-PHASE6: ALL OK")


if __name__ == "__main__":
    main()
