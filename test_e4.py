#!/usr/bin/env python3
"""E4 challenge.py labeling family check.

Validates that print-label extraction handles the real-world shapes that plain
``print('n =', n)`` misses: f-string prints (``print(f"n = {n}")``), f-string
hex field specs (``print(f"n = {n:x}")``), list/tuple prints
(``print((n, e, c))``) and mixed banner+data prints. Each case is a multi-file
RSA multi-prime challenge (primes only in the source) whose output uses one of
these print shapes; the solver must recover the flag at rank #1.
"""
import json
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_rsamultiprimefamily as M  # noqa: E402  (reuse rprime/flag)

BODIES = ["fstr", "hex", "tuple", "mix"]


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self._mp = M.Gen(seed)

    def rprime(self, bits):
        return self._mp.rprime(bits)

    def flag(self):
        p = "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz")
                     for _ in range(3))
        body = self.rng.choice(BODIES)
        return (p + "{" + body + "}").encode()

    def build(self, n=10):
        cases = []
        for i in range(n):
            f = self.flag()
            m = int.from_bytes(f, "big")
            primes = [self.rprime(90) for _ in range(4)]
            while any((pr - 1) % 65537 == 0 for pr in primes):
                primes = [self.rprime(90) for _ in range(4)]
            nmod = 1
            for pr in primes:
                nmod *= pr
            e = 65537
            c = pow(m, e, nmod)
            fmt = i % 4
            base = ("from Crypto.Util.number import bytes_to_long\n"
                    + "\n".join(f"p{k+1} = {pr}" for k, pr in enumerate(primes))
                    + f"\ne = {e}\n"
                    + "flag = open('flag.txt','rb').read()\n"
                    + "ct = pow(bytes_to_long(flag), e, n)\n")
            if fmt == 0:      # f-string decimal prints, per-value
                src = (base + "print(f\"n = {n}\")\n"
                       + "print(f\"e = {e}\")\nprint(f\"ct = {ct}\")\n").encode()
                data = f"n = {nmod}\ne = {e}\nct = {c}\n".encode()
            elif fmt == 1:    # f-string hex field specs
                src = (base + "print(f\"n = {n:x}\")\n"
                       + "print(f\"e = {e:x}\")\nprint(f\"ct = {ct:x}\")\n").encode()
                data = f"n = {nmod:x}\ne = {e:x}\nct = {c:x}\n".encode()
            elif fmt == 2:    # tuple print (bare values, ordering-dependent)
                src = (base + "print((n, e, ct))\n").encode()
                data = f"({nmod}, {e}, {c})\n".encode()
            else:             # banner text + tuple print
                src = (base + "print(\"params:\", (n, e, ct))\n").encode()
                data = f"params: ({nmod}, {e}, {c})\n".encode()
            cases.append((f"e4_{i}", data, src, f))
        return cases


def run_case_multi(data, src, timeout=20):
    """Run autocrypt on a multi-file pair (source + output) via tmp files."""
    Path("tm_e4.py").write_bytes(src)
    Path("tm_e4.txt").write_bytes(data or b"")
    r = subprocess.run([sys.executable, "autocrypt.py", "tm_e4.py", "tm_e4.txt",
                        "--timeout", str(timeout), "--json"],
                       capture_output=True, text=True, timeout=60)
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception:
        out = []
    return out


def main():
    g = Gen(20271105)
    cases = g.build()
    passed = 0
    for name, data, src, flag in cases:
        t0 = time.time()
        out = run_case_multi(data, src)
        wall = time.time() - t0
        want = flag.decode()
        rank = next((k for k, x in enumerate(out)
                     if want.lower() in x["plaintext"].lower()), None)
        if rank == 0 and wall < 8:
            passed += 1
            print(f"PASS {name} rank=0 wall={wall:.1f}s want={want}")
        else:
            print(f"FAIL {name} rank={rank} wall={wall:.1f}s want={want}")
            if out:
                print(f"     top={out[0]['chain'][:60]!r} {out[0]['plaintext'][:30]!r}")
    print(f"E4LABELFAMILY seed=20271105: {passed}/{len(cases)} (target: rank #1 and <8s)")


if __name__ == "__main__":
    main()
