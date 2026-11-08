#!/usr/bin/env python3
"""Hex-layer family generator (diagnosis + measurement).

Mirrors the E2b-fix5 family: a random classical cipher (vigenere / atbash /
xor) under 1-4 encoding layers (hex/base64/base32/binary), with the flag
style from test_blind2.py (random prefix + leet body).

Usage:
  python3 test_hexfamily.py <seed> [--dump] [--json <file> | --json <file> <idx>]
"""
import base64
import json
import random
import string
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

LEET_WORDS = ["c0de", "fl4g", "s3cr3t", "k3y", "x0r", "l33t", "h4ck",
               "c1ph3r", "r3v", "pwn", "m1sc", "w3b", "n0t", "eng1ish",
               "h3ll0", "w0rld", "t3st", "d4ta", "f1nd", "m4ny", "k3ys",
               "crypt0", "b4se", "h0me", "w4nt"]
ALPHA = string.ascii_letters + string.digits + "_"


class Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.AL = self.rng.choice(ALPHA)
        # keep a deterministic per-call RNG like make_fixtures
        self.rng2 = random.Random(seed + 1)

    def rand_flag(self):
        n = self.rng2.randint(4, 10)
        prefix = "".join(self.rng2.choice(ALPHA) for _ in range(n))
        k = self.rng2.randint(2, 4)
        body = "_".join(self.rng2.choice(LEET_WORDS) for _ in range(k))
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

    def vigenere(self, t, key):
        out, i = [], 0
        for c in t:
            if c.isalpha():
                k = ord(key[i % len(key)]) - 97
                b = 65 if c.isupper() else 97
                out.append(chr((ord(c) - b + k) % 26 + b))
                i += 1
            else:
                out.append(c)
        return "".join(out)

    def xor_bytes(self, b, key):
        return bytes(c ^ key[i % len(key)] for i, c in enumerate(b))

    def encode_layer(self, data):
        """One encoding layer, returns bytes."""
        r = self.rng2.randrange(4)
        if r == 0:
            return data.hex().encode()
        if r == 1:
            return base64.b64encode(data)
        if r == 2:
            return base64.b32encode(data)
        return "".join(f"{b:08b}" for b in data).encode()

    def encipher(self, c):
        f = self.rand_flag()
        if c == "vigenere":
            key = self.rng2.choice(["lemon", "secret", "key", "crypto", "flag",
                                    "ctf", "admin", "x"])
            data = self.vigenere(f, key).encode()
        elif c == "atbash":
            data = self.atbash(f).encode()
        else:  # xor
            L = self.rng2.randint(1, 3)
            key = bytes(self.rng2.randrange(33, 127) for _ in range(L))
            data = self.xor_bytes(f.encode(), key)
        return f, data

    def build(self, n=10, cipher=None, layers=None):
        cases = []
        for i in range(n):
            if cipher is None:
                c = self.rng2.choice(["vigenere", "atbash", "xor"])
                nl = layers[i % len(layers)] if layers else self.rng2.randint(1, 4)
            else:
                c = cipher[i % len(cipher)] if isinstance(cipher, list) else cipher
                nl = layers[i % len(layers)] if layers else self.rng2.randint(1, 4)
            f, data = self.encipher(c)
            name = f"{c}_L{nl}"
            for _ in range(nl):
                data = self.encode_layer(data)
            cases.append((name, data, f))
        return cases


def run_case(data_bytes, timeout=15):
    Path("tm.txt").write_bytes(data_bytes)
    r = subprocess.run([sys.executable, "autocrypt.py", "tm.txt",
                        "--timeout", str(timeout), "--json"],
                       capture_output=True, text=True, timeout=40)
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception:
        out = []
    return out


MATRIX = [  # (cipher, layers) fixed grid
    ("vigenere", 1), ("vigenere", 2), ("vigenere", 3), ("vigenere", 4),
    ("atbash", 2), ("atbash", 3), ("xor", 2), ("xor", 3),
    ("atbash", 4), ("xor", 1),
]
D12 = [  # depth 1-2 measurement grid
    ("vigenere", 1), ("vigenere", 2), ("atbash", 1), ("atbash", 2),
    ("xor", 1), ("xor", 2), ("vigenere", 1), ("vigenere", 2),
    ("xor", 2), ("atbash", 2),
]
D34 = [  # depth 3-4 measurement grid
    ("vigenere", 3), ("vigenere", 4), ("atbash", 3), ("atbash", 4),
    ("xor", 3), ("xor", 4), ("vigenere", 3), ("vigenere", 4),
    ("xor", 3), ("atbash", 4),
]


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 20270704
    g = Gen(seed)
    if "--matrix" in sys.argv:
        cases = g.build(10, cipher=[c for c, _ in MATRIX],
                        layers=[l for _, l in MATRIX])
    elif "--grid" in sys.argv:
        grid = D12 if sys.argv[sys.argv.index("--grid") + 1] == "d12" else D34
        cases = g.build(10, cipher=[c for c, _ in grid],
                        layers=[l for _, l in grid])
    else:
        cases = g.build(10)
    if "--dump" in sys.argv:
        for name, data, flag in cases:
            print(f"{name:14} {data[:40]!r} -> {flag}")
        return
    if "--json" in sys.argv:
        idx = None
        if len(sys.argv) > sys.argv.index("--json") + 1:
            try:
                idx = int(sys.argv[sys.argv.index("--json") + 1])
            except ValueError:
                pass
        targets = [idx] if idx is not None else range(len(cases))
        for i in targets:
            name, data, flag = cases[i]
            out = run_case(data)
            print(json.dumps({"idx": i, "name": name, "flag": flag,
                              "results": out}, indent=1))
        return
    passed = 0
    failed = []
    for i, (name, data, flag) in enumerate(cases):
        out = run_case(data)
        rank = next((k for k, x in enumerate(out)
                     if flag.lower() in x["plaintext"].lower()), None)
        if rank == 0:
            passed += 1
        else:
            failed.append((i, name, rank, out[0]["chain"][:60] if out else "-",
                           out[0]["plaintext"][:40] if out else "-"))
    print(f"HEXFAMILY seed={seed}: {passed}/{len(cases)}")
    for f in failed:
        print(f"  FAIL idx={f[0]} {f[1]:14} rank={f[2]} top={f[3]!r} {f[4]!r}")


if __name__ == "__main__":
    main()
