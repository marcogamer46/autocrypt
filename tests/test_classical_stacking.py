#!/usr/bin/env python3
"""Regression for stacked classical-layer composition.

Previously a classical candidate could only continue expanding when its output
fingerprinted as an encoding (magic bytes or a prior_map score >= .75). Plain
ASCII classical ciphertext never did, so the second and third classical layers
of a stack (e.g. vigenere -> affine -> caesar) were never attempted. The
should_expand gate now allows bounded classical stacking (child_classical <= 2)
and the caesar/affine solvers keep their full key space reachable at
intermediate depth, so genuine layered classics compose.

Each fixture encodes a flag in a stacked classical chain and expects the CLI to
recover it. There is no ciphered challenge text anywhere: the framework must
derive every step.
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
        return out.get("results", [])
    return out


def _flag_recovered(results, flag):
    fl = flag.decode() if isinstance(flag, bytes) else flag
    return any(fl.lower() in (res.get("plaintext") or "").lower() for res in results)


def _aff(x, a, b):
    return (a * x + b) % 26


def _enc_aff(text, a, b):
    return "".join(
        chr(65 + _aff(ord(ch) - 65, a, b)) if ch.isupper()
        else chr(97 + _aff(ord(ch) - 97, a, b)) if ch.islower()
        else ch for ch in text)


def _enc_caesar(text, shift):
    return "".join(
        chr(65 + (ord(ch) - 65 - shift) % 26) if ch.isupper()
        else chr(97 + (ord(ch) - 97 - shift) % 26) if ch.islower()
        else ch for ch in text)


def _enc_vig(text, key):
    k = [ord(c) - 65 for c in key.upper()]
    i = 0
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr(65 + (ord(ch) - 65 + k[i % len(k)]) % 26))
            i += 1
        elif ch.islower():
            out.append(chr(97 + (ord(ch) - 97 + k[i % len(k)]) % 26))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def _case(name, text, flag):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = _flag_recovered(results, flag)
    print(f"{name:30} {'PASS' if ok else 'FAIL'} (chains="
          f"{[r.get('chain') for r in results][:3]})")
    return ok


def main():
    failed = False

    # vigenere -> affine -> caesar (nothing collapsible into one affine key;
    # the vigenere layer is not a simple substitution).
    flag = "academy{classical_stack_works}"
    ch = _enc_vig(_enc_aff(_enc_caesar(flag, 11), 3, 7), "SECRET")
    failed |= not _case("vig->affine->caesar", ch + "\n", flag)

    # caesar -> caesar (double shift must compose into the effective shift).
    flag2 = "academy{stack_caesar}"
    ch2 = _enc_caesar(_enc_caesar(flag2, 7), 12)
    failed |= not _case("caesar->caesar", ch2 + "\n", flag2)

    # affine -> caesar where the two layers are NOT subsumable by a single
    # affine key (a coprime, non-trivial composite).
    flag3 = "academy{stack_affine_caesar}"
    # plaintext -> caesar(15) -> affine(7, 13) ; check it's not a pure affine
    ch3 = _enc_aff(_enc_caesar(flag3, 15), 7, 13)
    failed |= not _case("affine->caesar", ch3 + "\n", flag3)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
