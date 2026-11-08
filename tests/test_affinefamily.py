#!/usr/bin/env python3
"""J1a family check: compositions of {atbash, rot13, caesar(k), affine(a,b)}
on flag-shaped plaintext, seed 20270701. Includes 3 compound (multi-step,
non-single-named-key) cases; all are affine maps mathematically, but the
compound ones exercise the multi-step encode path."""
import random
import string
import sys
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

    def rand_flag(self):
        n = self.rng.randint(4, 10)
        prefix = "".join(self.rng.choice(ALPHA) for _ in range(n))
        k = self.rng.randint(2, 4)
        body = "_".join(self.rng.choice(LEET_WORDS) for _ in range(k))
        return prefix + "{" + body + "}"

    def caesar(self, t, k):
        out = []
        for c in t:
            if "a" <= c <= "z":
                out.append(chr((ord(c) - 97 + k) % 26 + 97))
            elif "A" <= c <= "Z":
                out.append(chr((ord(c) - 65 + k) % 26 + 65))
            else:
                out.append(c)
        return "".join(out)

    def atbash(self, t):
        return "".join(chr(155 - ord(c)) if c.isupper() else chr(219 - ord(c))
                       if c.islower() else c for c in t)

    def affine(self, t, a, b):
        out = []
        for c in t:
            if c.islower():
                out.append(chr(97 + (a * (ord(c) - 97) + b) % 26))
            elif c.isupper():
                out.append(chr(65 + (a * (ord(c) - 65) + b) % 26))
            else:
                out.append(c)
        return "".join(out)

    def build(self):
        cases = []
        named = [
            ("atbash", lambda f: self.atbash(f)),
            ("rot13", lambda f: self.caesar(f, 13)),
            ("caesar4", lambda f: self.caesar(f, 4)),
            ("caesar23", lambda f: self.caesar(f, 23)),
            ("affine3_7", lambda f: self.affine(f, 3, 7)),
            ("affine25_12", lambda f: self.affine(f, 25, 12)),
            ("affine9_20", lambda f: self.affine(f, 9, 20)),
        ]
        compound = [
            ("c9_a_c15", lambda f: self.caesar(self.atbash(self.caesar(f, 9)), 15)),
            ("a_a17_r13", lambda f: self.caesar(self.affine(self.atbash(f), 17, 5), 13)),
            ("a25_c18", lambda f: self.caesar(self.affine(f, 25, 12), 18)),
        ]
        for name, fn in named + compound:
            f = self.rand_flag()
            cases.append((name, fn(f).encode(), f))
        return cases


def main():
    g = Gen(20270701)
    cases = g.build()
    passed = 0
    for name, data, flag in cases:
        out = H.run_case(data)
        rank = next((k for k, x in enumerate(out)
                     if flag.lower() in x["plaintext"].lower()), None)
        if rank == 0:
            passed += 1
        else:
            print(f"FAIL {name:14} rank={rank} want={flag}")
            if out:
                print(f"     top={out[0]['chain'][:60]!r} {out[0]['plaintext'][:36]!r}")
    print(f"AFFINEFAMILY seed=20270701: {passed}/10")


if __name__ == "__main__":
    main()
