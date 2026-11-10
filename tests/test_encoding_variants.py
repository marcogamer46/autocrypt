#!/usr/bin/env python3
"""Regression for the encoding-variant improvements:

  * fingerprint() now detects base32hex and Crockford base32 (they were
    referenced but never produced as classes/hypotheses), so payloads in
    those encodings are surfaced and prioritized rather than only reachable
    via generic catch-all solvers;
  * solve_base64 gains a case-swapped-alphabet fallback, so a base64 payload
    whose lower/upper cases are swapped is recovered through the main base64
    path too.

Each fixture encodes a flag in the variant encoding and expects the CLI to
recover it. A prose negative-control asserts no spurious variant classes.
"""
import sys
import subprocess
import tempfile
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _cli_results(p):
    args = [sys.executable, "-m", "autocrypt.cli", str(p), "--json", "--top", "200"]
    r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
    try:
        out = json.loads(r.stdout or "[]")
    except Exception:
        return [], {}
    if isinstance(out, dict):
        return out.get("results", []), out.get("fingerprint", {})
    return out, {}


def _flag_recovered(results, flag):
    fl = flag.decode() if isinstance(flag, bytes) else flag
    return any(fl.lower() in (res.get("plaintext") or "").lower() for res in results)


def _case(name, text, flag):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results, fp = _cli_results(p)
    ok = _flag_recovered(results, flag)
    note = "flag recovered" if ok else "flag NOT recovered"
    print(f"{name:22} {'PASS' if ok else 'FAIL'} ({note}; chains="
          f"{[r.get('chain') for r in results][:3]})")
    return ok, fp


def _b32hex(data):
    # standard-library b32hexencode
    import base64 as b64
    return b64.b32hexencode(data).decode().rstrip("=")


def _crockford(data):
    ck = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    # encode as a big integer in base 32 (Crockford)
    n = int.from_bytes(data, "big")
    if n == 0:
        return "0"
    out = []
    while n:
        out.append(ck[n % 32])
        n //= 32
    return "".join(reversed(out))


def main():
    import base64
    failed = False

    # ---- base32hex
    flag = b"academy{enc_var_b32hex}"
    tok = _b32hex(flag)
    failed |= not _case("base32hex", f"{tok}\n", flag)[0]

    # ---- Crockford base32
    flag2 = b"academy{enc_var_crockford}"
    tok2 = _crockford(flag2)
    failed |= not _case("crockford", f"{tok2}\n", flag2)[0]

    # ---- swapped-case base64
    flag3 = b"academy{enc_var_swapcase}"
    tok3 = base64.b64encode(flag3).decode().swapcase()
    failed |= not _case("swapcase-b64", f"{tok3}\n", flag3)[0]

    # ---- fingerprint actually emits the variant classes
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "b32hex.txt"
        p.write_text(_b32hex(flag), encoding="utf-8")
        _, fp = _cli_results(p)
    classes = fp.get("classes", [])
    has_b32hex = "base32hex" in classes
    print(f"{'fp-emits-base32hex':22} {'PASS' if has_b32hex else 'FAIL'} "
          f"(classes={classes})")
    failed |= not has_b32hex

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "cck.txt"
        p.write_text(_crockford(flag2), encoding="utf-8")
        _, fp = _cli_results(p)
    classes = fp.get("classes", [])
    has_cck = "crockford" in classes
    print(f"{'fp-emits-crockford':22} {'PASS' if has_cck else 'FAIL'} "
          f"(classes={classes})")
    failed |= not has_cck

    # ---- prose negative-control: no variant classes on plain English
    prose = ("The quick brown fox jumps over the lazy dog while the "
             "other animals watch from the nearby forest every morning.")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "prose.txt"
        p.write_text(prose, encoding="utf-8")
        _, fp = _cli_results(p)
    classes = fp.get("classes", [])
    bad = [c for c in classes if c in ("base32hex", "crockford", "z85")]
    ok = not bad
    print(f"{'prose-no-variant-classes':22} {'PASS' if ok else 'FAIL'} "
          f"(variant classes={bad})")
    failed |= not ok

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
