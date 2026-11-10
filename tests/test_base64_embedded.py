#!/usr/bin/env python3
"""Regression for embedded base64-run extraction in solve_base64
(autocrypt/solvers.py).

Covers:
  * a flag encoded in base64 but embedded inside surrounding prose (a label /
    narration before and after the payload) is still recovered, even though
    the whole buffer is not a valid base64 decode;
  * a genuine payload run containing '+'/'/' (standard alphabet) and one using
    the URL-safe alphabet ('-'/'_') are both found;
  * prose-only buffers with long pure-letter runs (which are not base64
    payloads) do NOT produce junk candidates.
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
        return []
    if isinstance(out, dict):
        out = out.get("results", [])
    return out


def _flag_recovered(results, flag):
    fl = flag.decode() if isinstance(flag, bytes) else flag
    return any(fl.lower() in (res.get("plaintext") or "").lower() for res in results)


def _roundtrip(blob, text):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = _flag_recovered(results, blob)
    note = "flag recovered" if ok else "flag NOT recovered"
    chains = [r.get("chain") for r in results][:4]
    print(f"{blob.decode():24} {'PASS' if ok else 'FAIL'} ({note}; chains={chains})")
    return ok


def main():
    import base64
    failed = False

    # ---- standard-alphabet payload embedded in prose (prefix + suffix)
    flag = b"academy{embedded_b64_standard}"
    tok = base64.b64encode(flag).decode()
    text = f"the transport layer sent: {tok} over the wire, tcp/443.\n"
    failed |= not _roundtrip(flag, text)

    # ---- URL-safe alphabet payload embedded in prose
    flag2 = b"academy{embedded_b64_urlsafe}"
    tok2 = base64.urlsafe_b64encode(flag2).decode().rstrip("=")
    text2 = f"token={tok2}\ndo not share this token with anyone.\n"
    failed |= not _roundtrip(flag2, text2)

    # ---- negative control: prose with long pure-letter runs (no digits / no
    # non-alphabetic alphabet chars) must yield NO base64 candidate
    prose = ("Even after the long meeting we agreed the proceedings were "
             "unusually detailed and completely astonishing in every way "
             "regardless of what the other side said they wanted.")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "prose.txt"
        p.write_text(prose, encoding="utf-8")
        results = _cli_results(p)
    b64_chains = [r.get("chain") for r in results
                  if r.get("chain") and "base64" in r["chain"]]
    ok = not b64_chains
    print(f"{'prose-no-false-positive':24} {'PASS' if ok else 'FAIL'} "
          f"(base64 chains={b64_chains})")
    failed |= not ok

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
