#!/usr/bin/env python3
"""Regression for the gap-filling solvers introduced in 0.10.3:

  * ``powershell-encodedcommand`` - base64 of UTF-16LE (PowerShell
    -EncodedCommand) is decoded back to readable text containing the flag.
  * ``unicode-tag-stego`` - Unicode tag characters (U+E0000..E007F) map to
    ASCII and recover the flag.
  * ``java-random`` - recovers a java.util.Random seed from consecutive
    nextInt() outputs; the seed matches and >3 outputs confirm.
  * ``jwt-key-confusion`` - an RS256-header JWT whose signature is an HMAC
    keyed with the RSA public key resolves to the payload flag.

Each fixture feeds the CLI and asserts the flag (or the recovery marker) shows
up in the JSON results.
"""
import sys
import json
import base64
import hmac
import hashlib
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_RND_A = 0x5DEECE66D
_RND_B = 0xB
_RND_MASK = (1 << 48) - 1


def _cli_results(p):
    args = [sys.executable, "-m", "autocrypt.cli", str(p), "--json", "--top", "200"]
    r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
    try:
        out = json.loads(r.stdout or "[]")
    except Exception:
        return []
    if isinstance(out, dict):
        return out.get("results", [])
    return out


def _flag_recovered(results, flag):
    fl = flag.decode() if isinstance(flag, bytes) else flag
    return any(fl.lower() in (res.get("plaintext") or "").lower() for res in results)


def _case(name, text, flag):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = _flag_recovered(results, flag)
    print(f"{name:24} {'PASS' if ok else 'FAIL'} (methods="
          f"{[r.get('method') for r in results][:4]})")
    return ok


def _case_marker(name, text, marker, expect=True):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = any(marker in (r.get("plaintext") or "") for r in results)
    passed = ok if expect else not ok
    print(f"{name:24} {'PASS' if passed else 'FAIL'} ({'found' if ok else 'absent'} "
          f"marker; methods={[r.get('method') for r in results][:4]})")
    return passed


def _rnd_ints(seed, n):
    s = (seed ^ _RND_A) & _RND_MASK
    out = []
    for _ in range(n):
        s = (s * _RND_A + _RND_B) & _RND_MASK
        v = s >> 16
        out.append(v - (1 << 32) if v >= (1 << 31) else v)
    return out


def _jwt(secret, flag):
    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")
    head = b64u(b'{"alg":"RS256","typ":"JWT"}')
    pay = b64u(json.dumps({"flag": flag}).encode())
    msg = head + b"." + pay
    sig = b64u(hmac.new(secret, msg, hashlib.sha256).digest())
    return (msg + b"." + sig).decode()


def main():
    failed = False

    # ---- PowerShell -EncodedCommand: base64 of UTF-16LE
    flag1 = b"academy{gap_ps_encoded}"
    ps = base64.b64encode(flag1.decode().encode("utf-16-le")).decode()
    failed |= not _case("powershell-encoded", f"{ps}\n", flag1)

    # ---- Unicode tag stego
    flag2 = "academy{gap_unicode_tag}"
    tagified = "".join(chr(ord(c) + 0xE0000) for c in flag2)
    prose = "Some normal chat text here " + tagified + " and more context."
    failed |= not _case("unicode-tag", prose, flag2)

    # ---- java.util.Random seed recovery
    seed = 0xDEAD_BEEF
    ints = _rnd_ints(seed, 5)
    jtext = "Random outputs: " + ", ".join(str(i) for i in ints) + "."
    failed |= not _case_marker("java-random", jtext, f"seed {seed}")

    # ---- JWT RS256->HS256 key confusion
    der = b"FAKE-DER-KEY-MATERIAL-0123456789ABCDEF" * 4
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + base64.b64encode(der).decode()
           + "\n-----END PUBLIC KEY-----")
    flag4 = "academy{gap_jwt_confusion}"
    tok = _jwt(der, flag4)
    failed |= not _case("jwt-key-confusion", pem + "\n" + tok + "\n", flag4)

    # ---- Java-random negative control: unrelated integers must NOT fire
    decoy = "The scores were 42, 7, 1337, 9001, 12345."
    failed |= not _case_marker("java-random-negative", decoy, "seed=", expect=False)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
