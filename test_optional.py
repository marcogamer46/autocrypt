#!/usr/bin/env python3
"""D4: AES + Fernet solver tests with SKIP rows when optional libraries are absent.

Each row prints `NAME STATUS seconds`. STATUS is one of:
  PASS  - library installed, autocrypt recovered the plaintext
  FAIL  - library installed but recovery failed (regression)
  SKIP  - optional library not installed (Crypto / cryptography)

Exit code is 0 unless a non-SKIP row fails.
"""
import subprocess
import sys
import time
from pathlib import Path

TMP = Path(__file__).resolve().parent / "fixtures"
TMP.mkdir(parents=True, exist_ok=True)


def run_autocrypt(data: bytes, expect: str, timeout=25):
    f = TMP / "optional_case.txt"
    f.write_bytes(data)
    t0 = time.monotonic()
    out = subprocess.run(
        [sys.executable, "autocrypt.py", str(f), "--timeout", "15"],
        capture_output=True, text=True, timeout=timeout)
    secs = time.monotonic() - t0
    return expect in out.stdout, secs


def row(name, status, secs):
    print(f"{name:12} {status:5} {secs:7.1f}")
    return status == "FAIL"


failed = False

# ------------------------------------------------ AES (pycryptodome)
try:
    from Crypto.Cipher import AES
    aes_ok = True
except Exception:
    aes_ok = False

if aes_ok:
    try:
        key = b"0123456789abcdef"          # 16 bytes
        msg = b"academy{aes_key_works}".ljust(32, b" ")
        ct = AES.new(key, AES.MODE_ECB).encrypt(msg)
        data = f"key={key.hex()}\nmode=ecb\n{ct.hex()}\n".encode()
        ok, secs = run_autocrypt(data, "academy{aes_key_works}")
        failed |= row("aes_key", "PASS" if ok else "FAIL", secs)
    except Exception as e:
        failed |= row("aes_key", "FAIL", 0.0)
        print("   (exception while building/running AES case:", e, ")")
else:
    failed |= row("aes_key", "SKIP", 0.0)

# ------------------------------------------------ Fernet (cryptography)
try:
    from cryptography.fernet import Fernet
    fernet_ok = True
except Exception:
    fernet_ok = False

if fernet_ok:
    try:
        k = Fernet.generate_key()
        token = Fernet(k).encrypt(b"academy{fernet_key_works}")
        data = f"key={k.decode()}\n{token.decode()}\n".encode()
        ok, secs = run_autocrypt(data, "academy{fernet_key_works}")
        failed |= row("fernet_key", "PASS" if ok else "FAIL", secs)
    except Exception as e:
        failed |= row("fernet_key", "FAIL", 0.0)
        print("   (exception while building/running Fernet case:", e, ")")
else:
    failed |= row("fernet_key", "SKIP", 0.0)

sys.exit(1 if failed else 0)
