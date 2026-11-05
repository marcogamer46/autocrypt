#!/usr/bin/env python3
"""RSA multi-prime (crowded) family check — mirrors the real picoCTF
"Many Prime" challenge shape: 4 primes of similar size, e=65537, modulus
printed; primes sometimes only in the source (multi-file), sometimes labeled
in the file. Fresh seed 20271105. Target: rank #1, each < 5 s (no factoring
when the primes are given; source hint propagation must feed the solver)."""
import json
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_hexfamily as H

BODIES = ["mul71", "rsa", "cr0wd3d", "m4ny"]


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)

    def rprime(self, bits):
        while True:
            n = self.rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if all(n % d for d in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                                   31, 37, 41, 43, 47)):
                d, s = n - 1, 0
                while d % 2 == 0:
                    d //= 2
                    s += 1
                ok = True
                for a in (2, 3, 5, 7, 11, 13):
                    x = pow(a, d, n)
                    if x in (1, n - 1):
                        continue
                    for _ in range(s - 1):
                        x = x * x % n
                        if x == n - 1:
                            break
                    else:
                        ok = False
                        break
                if ok:
                    return n

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
            if fmt == 0:      # single-file, all primes labeled decimal (with n)
                data = ("\n".join(f"p{k+1} = {pr}" for k, pr in enumerate(primes))
                        + f"\ne = {e}\nc = {c}\nn = {nmod}\n").encode()
                src = b""
            elif fmt == 1:    # single-file, labeled hex (with n)
                data = ("\n".join(f"p{k+1} = 0x{pr:x}" for k, pr in enumerate(primes))
                        + f"\ne = 0x{e:x}\nc = 0x{c:x}\nn = 0x{nmod:x}\n").encode()
                src = b""
            elif fmt == 2:    # multi-file: source holds primes, output holds n/e/c
                data = f"n = {nmod}\ne = {e}\nc = {c}\n".encode()
                src = ("from Crypto.Util.number import bytes_to_long\n"
                       + "\n".join(f"p{k+1} = {pr}" for k, pr in enumerate(primes))
                       + f"\ne = {e}\n"
                       + "flag = open('flag.txt','rb').read()\n"
                       + "ct = pow(bytes_to_long(flag), e, n)\n"
                       + "print('n =', n)\nprint('e =', e)\nprint('ct =', ct)\n").encode()
            else:             # multi-file: hex in both source and output
                data = f"n = 0x{nmod:x}\ne = 0x{e:x}\nc = 0x{c:x}\n".encode()
                src = ("from Crypto.Util.number import bytes_to_long\n"
                       + "\n".join(f"p{k+1} = 0x{pr:x}" for k, pr in enumerate(primes))
                       + f"\ne = 0x{e:x}\n"
                       + "flag = open('flag.txt','rb').read()\n"
                       + "ct = pow(bytes_to_long(flag), e, n)\n"
                       + "print('n =', hex(n))\nprint('e =', hex(e))\nprint('ct =', hex(ct))\n").encode()
            cases.append((f"mp_{i}", data, src, f))
        return cases


def run_case_multi(data, src, timeout=20):
    """Run autocrypt on a multi-file pair (source + output) via tmp files."""
    Path("tm.py").write_bytes(src)
    Path("tm.txt").write_bytes(data)
    r = subprocess.run(["python3", "autocrypt.py", "tm.py", "tm.txt",
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
        if src:
            out = run_case_multi(data, src)
        else:
            out = H.run_case(data, timeout=20)
        wall = time.time() - t0
        want = flag.decode()
        rank = next((k for k, x in enumerate(out)
                     if want.lower() in x["plaintext"].lower()), None)
        if rank == 0 and wall < 5:
            passed += 1
            print(f"PASS {name} rank=0 wall={wall:.1f}s want={want}")
        else:
            print(f"FAIL {name} rank={rank} wall={wall:.1f}s want={want}")
            if out:
                print(f"     top={out[0]['chain'][:60]!r} {out[0]['plaintext'][:30]!r}")
    print(f"RSAMULTIPRIMEFAMILY seed=20271105: {passed}/{len(cases)} (target: rank #1 and <5s)")


if __name__ == "__main__":
    main()
