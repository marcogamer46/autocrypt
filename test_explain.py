#!/usr/bin/env python3
"""E5: verify ``--explain`` emits a plain-English line for each recovery chain.

Checks the explain_chain mapping directly (unit) and runs a couple of real
challenges through the CLI with --explain to confirm it prints a line that is
not the raw chain (i.e. the human-readable layer is actually emitted).
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from explain import explain_chain  # noqa: E402

# (chain, expected-substring)
CASES = [
    ("base64 -> caesar(shift=7)", "Base64"),
    ("RSA known p+q", "p+q"),
    ("New-Caesar b16 (key=chr(98))", "nibble"),
    ("base32 -> ROT13 -> reversed-text", "Reversed"),
    ("RSA factored(d=1,e=65537,m=2,n=3)", "RSA broken"),
    ("quoted-printable -> as-is", "quoted-printable"),
]


def main():
    failures = 0
    for chain, want in CASES:
        lines = explain_chain(chain)
        joined = " ".join(lines)
        ok = want.lower() in joined.lower() and lines
        print(f"{'PASS' if ok else 'FAIL'}  {chain!r} -> {joined!r}")
        if not ok:
            failures += 1

    # CLI smoke: real Sum-O-Primes must show an explanation line under its rank.
    PY = sys.executable
    r = subprocess.run(
        [PY, str(ROOT / "autocrypt.py"),
         str(ROOT / "real_challenges" / "sumoprimes" / "gen.py"),
         str(ROOT / "real_challenges" / "sumoprimes" / "output.txt"),
         "--top", "1", "--timeout", "12", "--explain"],
        capture_output=True, text=True, timeout=60)
    out = r.stdout
    if "RSA broken via p+q leak" in out:
        print("PASS  CLI --explain (Sum-O-Primes) shows p+q explanation")
    else:
        print("FAIL  CLI --explain (Sum-O-Primes) missing explanation line")
        print("      got:", out[-400:])
        failures += 1

    print(f"\nE5EXPLAIN: {len(CASES) + 1 - failures}/{len(CASES) + 1} OK")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
