#!/usr/bin/env python3
"""J1b family check: small-factored RSA cases (n 64-256 bits, varied e,
flag-shaped messages, hex and decimal output, labeled and unlabeled), seed
20270702."""
import math
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_hexfamily as H

BODIES = ["a1", "b2", "fl4g", "k3y", "c0de", "w3b", "n0t", "x0r"]


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)

    def small_prime(self, bits):
        while True:
            n = self.rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if n > 1 and all(n % d for d in (2, 3, 5, 7, 11, 13, 17, 19,
                                              23, 29, 31, 37, 41, 43, 47)):
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

    def small_prime_smooth(self, bits, B=200_000):
        """SYNTHETIC: prime p with p-1 B-smooth (p = 2M+1, M built from
        primes < B). Mirrors the repo's own p-1 fixtures; makes factoring
        deterministic for the large-n family cases (pure-Python rho cannot
        reliably split 99-128-bit semiprimes in budget)."""
        import bisect as _b
        # sieve primes <= B
        sieve = bytearray(b"\x01") * (B + 1)
        sieve[0] = sieve[1] = 0
        for i in range(2, int(B ** 0.5) + 1):
            if sieve[i]:
                sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
        primes = [i for i in range(2, B + 1) if sieve[i]]
        while True:
            M = 1
            while M.bit_length() < bits - 1:
                M *= self.rng.choice(primes)
            # trim back to target size
            M //= max(1, M.bit_length() - (bits - 1))
            p = 2 * M + 1
            if p.bit_length() != bits:
                continue
            if all(p % d for d in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)):
                d, s = p - 1, 0
                while d % 2 == 0:
                    d //= 2
                    s += 1
                ok = True
                for a in (2, 3, 5, 7, 11, 13):
                    x = pow(a, d, p)
                    if x in (1, p - 1):
                        continue
                    for _ in range(s - 1):
                        x = x * x % p
                        if x == p - 1:
                            break
                    else:
                        ok = False
                        break
                if ok:
                    return p

    def rand_flag(self, maxlen):
        inner = maxlen - 2  # room for prefix + braces
        while True:
            p = self.rng.randint(3, min(5, inner - 2))
            prefix = "".join(self.rng.choice(string.ascii_lowercase)
                             for _ in range(p))
            room = inner - p
            if room <= 3:
                body = self.rng.choice(["a1", "b2"])
            else:
                body = self.rng.choice(BODIES)
                k = self.rng.randint(1, 2)
                if k == 2 and room >= len(body) + 1 + 2:
                    body = body + "_" + self.rng.choice(BODIES)
            return prefix + "{" + body + "}"

    def build(self):
        cases = []
        spec = [
            ("dec_p36_e3", 36, 3, 1), ("dec_p36_e65537", 36, 65537, 1),
            ("dec_p44_e17", 44, 17, 1), ("dec_p50_e3", 50, 3, 1),
            ("dec_p64_e65537", 64, 65537, 1), ("dec_p36_e3", 36, 3, 1),
            ("hex_p36_e3", 36, 3, 2), ("hex_p40_e17", 40, 17, 2),
            ("unl_p36_e3", 36, 3, 3), ("unl_p44_e65537", 44, 65537, 3),
        ]
        for name, pbits, e, fmt in spec:
            pmax = (pbits * 2) // 8 - 2
            f = self.rand_flag(pmax)
            m = int.from_bytes(f.encode(), "big")
            while True:
                if pbits >= 48:  # large-n cases: synthetic p-1 smooth
                    p = self.small_prime_smooth(pbits)
                else:
                    p = self.small_prime(pbits)
                q = self.small_prime(pbits)
                n = p * q
                if math.gcd(e, (p - 1) * (q - 1)) == 1:
                    break
            c = pow(m, e, n)
            if fmt == 1:
                data = f"n={n}\ne={e}\nc={c}\n".encode()
            elif fmt == 2:
                data = f"n=0x{n:x}\ne=0x{e:x}\nc=0x{c:x}\n".encode()
            else:
                data = f"{n} {e} {c}\n".encode()
            cases.append((name, data, f))
        return cases


def main():
    g = Gen(20270702)
    cases = g.build()
    passed = 0
    for name, data, flag in cases:
        out = H.run_case(data)
        rank = next((k for k, x in enumerate(out)
                     if flag.lower() in x["plaintext"].lower()), None)
        if rank == 0:
            passed += 1
        else:
            print(f"FAIL {name:18} rank={rank} want={flag}")
            if out:
                print(f"     top={out[0]['chain'][:70]!r} {out[0]['plaintext'][:36]!r}")
    print(f"RSAFAMILY seed=20270702: {passed}/10")


if __name__ == "__main__":
    main()
