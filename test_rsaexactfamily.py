#!/usr/bin/env python3
"""c05 fix check: RSA small-e exact-root flags with underscore/leet-heavy
bodies; each must solve in < 3 s wall (fresh seed 20270721)."""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_hexfamily as H

BODIES = ["fl4g_m4ny_k3ys_c0de", "s3cr3t_w0rld_h3ll0_n0t",
          "eng1ish_b4se_x0r_c1ph3r", "h4ck_m1sc_pwn_w3b",
          "r3v_d4ta_l33t_h0me"]


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
                     for _ in range(5))
        return (p + "{" + self.rng.choice(BODIES) + "}").encode()

    def build(self):
        cases = []
        for i in range(10):
            f = self.flag()
            m = int.from_bytes(f, "big")
            p, q = self.rprime(512), self.rprime(512)
            n = p * q
            e = 3
            assert m ** e < n
            c = m ** e
            cases.append((f"exact_{i}", f"n={n}\ne={e}\nc={c}\n".encode(), f))
        return cases


def main():
    g = Gen(20270721)
    cases = g.build()
    passed = 0
    for name, data, flag in cases:
        t0 = time.time()
        out = H.run_case(data, timeout=20)
        wall = time.time() - t0
        want = flag.decode()
        rank = next((k for k, x in enumerate(out)
                     if want.lower() in x["plaintext"].lower()), None)
        if rank == 0 and wall < 3:
            passed += 1
        else:
            print(f"FAIL {name} rank={rank} wall={wall:.1f}s want={want}")
    print(f"RSAEXACTFAMILY seed=20270721: {passed}/10 (target: rank #1 <3s)")


if __name__ == "__main__":
    main()
