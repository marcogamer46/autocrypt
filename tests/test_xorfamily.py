#!/usr/bin/env python3
"""J1c family check: repeating-key XOR (key length 2-5) with mixed wrappers
(raw / hex / base64), flags with unknown prefixes of different lengths, some
short (<=20 chars). Fresh seed 20270703. Target >= 9/10 rank #1, each case
< 10 s."""
import base64
import random
import string
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_hexfamily as H

LEET_WORDS = ["c0de", "fl4g", "s3cr3t", "k3y", "x0r", "l33t", "h4ck",
               "c1ph3r", "r3v", "pwn", "m1sc", "w3b", "n0t", "eng1ish",
               "h3ll0", "w0rld", "t3st", "d4ta", "f1nd", "m4ny", "k3ys",
               "crypt0", "b4se", "h0me", "w4nt"]
ALPHA = string.ascii_letters + string.digits + "_"


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)

    def rand_flag(self, short=False, minlen=1, maxlen=80):
        while True:
            n = self.rng.randint(2 if short else 3, 5 if short else 10)
            prefix = "".join(self.rng.choice(ALPHA) for _ in range(n))
            k = self.rng.randint(1, 2) if short else self.rng.randint(2, 4)
            body = "_".join(self.rng.choice(LEET_WORDS) for _ in range(k))
            f = prefix + "{" + body + "}"
            if minlen <= len(f) <= maxlen:
                return f

    def xor_bytes(self, b, key):
        return bytes(c ^ key[i % len(key)] for i, c in enumerate(b))

    def build(self):
        cases = []
        for i in range(10):
            L = self.rng.randint(2, 5)
            if L >= 4:
                # short-ish flags (12..20 chars): covers "some short" without
                # dropping below the 12-byte repeating-XOR prior gate
                f = self.rand_flag(short=True, minlen=12, maxlen=20)
            elif i % 3 == 0:
                # raw (unwrapped) cases must stay >= 12 bytes for the
                # repeating-XOR prior gate
                f = self.rand_flag(False, minlen=12)
            else:
                f = self.rand_flag(False)
            key = bytes(self.rng.randrange(33, 127) for _ in range(L))
            data = self.xor_bytes(f.encode(), key)
            w = i % 3
            if w == 1:
                data = data.hex().encode()
            elif w == 2:
                data = base64.b64encode(data)
            cases.append((f"xor{L}_w{w}", data, f))
        return cases


def main():
    g = Gen(20270703)
    cases = g.build()
    passed = 0
    for name, data, flag in cases:
        t0 = time.time()
        out = H.run_case(data)
        wall = time.time() - t0
        rank = next((k for k, x in enumerate(out)
                     if flag.lower() in x["plaintext"].lower()), None)
        if rank == 0:
            passed += 1
        else:
            print(f"FAIL {name:12} rank={rank} wall={wall:.1f}s want={flag}")
            if out:
                print(f"     top={out[0]['chain'][:60]!r} {out[0]['plaintext'][:36]!r}")
        if wall >= 10:
            print(f"SLOW {name} wall={wall:.1f}s")
    print(f"XORFAMILY seed=20270703: {passed}/10")


if __name__ == "__main__":
    main()
