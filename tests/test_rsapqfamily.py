#!/usr/bin/env python3
"""J1b/c06 family check: RSA with p and q printed (e, c, optional n), any
common format: labeled/unlabeled, decimal/hex, p/q order swapped, with and
without n. Fresh seed 20270720. Target: rank #1, each < 2 s."""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_hexfamily as H

BODIES = ["a1", "b2", "fl4g", "k3y"]


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

    def build(self):
        cases = []
        for i in range(10):
            f = self.flag()
            m = int.from_bytes(f, "big")
            p, q = self.rprime(256), self.rprime(256)
            while (p - 1) % 65537 == 0 or (q - 1) % 65537 == 0:
                p, q = self.rprime(256), self.rprime(256)
            n = p * q
            e = 65537
            c = pow(m, e, n)
            fmt = i % 6
            if fmt == 0:      # labeled decimal, with n
                data = f"p = {p}\nq = {q}\ne = {e}\nc = {c}\nn = {n}\n".encode()
            elif fmt == 1:    # labeled decimal, no n
                data = f"p = {p}\nq = {q}\ne = {e}\nc = {c}\n".encode()
            elif fmt == 2:    # labeled hex, no n
                data = f"p = 0x{p:x}\nq = 0x{q:x}\ne = 0x{e:x}\nc = 0x{c:x}\n".encode()
            elif fmt == 3:    # labeled hex, with n
                data = f"p = 0x{p:x}\nq = 0x{q:x}\ne = 0x{e:x}\nc = 0x{c:x}\nn = 0x{n:x}\n".encode()
            elif fmt == 4:    # p/q order swapped, labeled
                data = f"q = {q}\np = {p}\ne = {e}\nc = {c}\n".encode()
            else:             # unlabeled lines, p q e c order, no n
                data = f"{p}\n{q}\n{e}\n{c}\n".encode()
            cases.append((f"pq_{i}", data, f))
        return cases


def main():
    g = Gen(20270720)
    cases = g.build()
    passed = 0
    for name, data, flag in cases:
        t0 = time.time()
        out = H.run_case(data, timeout=20)
        wall = time.time() - t0
        want = flag.decode()
        rank = next((k for k, x in enumerate(out)
                     if want.lower() in x["plaintext"].lower()), None)
        if rank == 0 and wall < 2:
            passed += 1
        else:
            print(f"FAIL {name} rank={rank} wall={wall:.1f}s want={want}")
            if out:
                print(f"     top={out[0]['chain'][:60]!r} {out[0]['plaintext'][:30]!r}")
    print(f"RSAPQFAMILY seed=20270720: {passed}/10 (target: rank #1 and <2s)")


if __name__ == "__main__":
    main()
