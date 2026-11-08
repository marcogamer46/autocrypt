#!/usr/bin/env python3
"""Fresh-seed family checks for the A-group + c15 fixes:
  c09 common-modulus, c11 Franklin-Reiter, c13 hash-crack, c15 sep-hex.
Each family: 10 cases on a fresh seed, rank #1 + <3s. Also negative decoys
must yield 0 flag false positives."""
import hashlib
import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_hexfamily as H

BODIES = ["fl4g_m4ny_k3ys", "s3cr3t_h0me", "eng1ish_b4se_x0r",
          "h4ck_m1sc_pwn", "r3v_d4ta_l33t"]


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
                     for _ in range(4))
        return (p + "{" + self.rng.choice(BODIES) + "}").encode()

    def wants_common(self):
        f = self.flag()
        m = int.from_bytes(f, "big")
        p, q = self.rprime(384), self.rprime(384)
        n = p * q
        exps = [(17, 65537), (5, 7), (13, 65537), (3, 11), (7, 65537)]
        e1, e2 = exps[self.rng.randrange(len(exps))]
        c1, c2 = pow(m, e1, n), pow(m, e2, n)
        fmt = self.rng.randrange(6)
        if fmt == 0:
            data = f"n = {n}\ne1 = {e1}\nc1 = {c1}\ne2 = {e2}\nc2 = {c2}\n".encode()
        elif fmt == 1:
            data = f"n={n}\ne1={e1}\nc1={c1}\ne2={e2}\nc2={c2}\n".encode()
        elif fmt == 2:
            data = (f"n = 0x{n:x}\ne1 = 0x{e1:x}\nc1 = 0x{c1:x}\n"
                    f"e2 = 0x{e2:x}\nc2 = 0x{c2:x}\n").encode()
        elif fmt == 3:
            data = f"n {n}\ne1 {e1}\nc1 {c1}\ne2 {e2}\nc2 {c2}\n".encode()
        elif fmt == 4:
            data = (f"e1={e1} c1={c1}\ne2={e2} c2={c2}\nn={n}\n").encode()
        else:
            data = f"n = {n}\nc1 = {c1} e1 = {e1}\nc2 = {c2} e2 = {e2}\n".encode()
        return "common", data, f

    def wants_fr(self):
        f = self.flag()
        m = int.from_bytes(f, "big")
        a = self.rng.choice([1, 2, 3, 5])
        b = self.rng.choice([1, 2])
        p, q = self.rprime(384), self.rprime(384)
        n = p * q
        e = 3
        c1 = pow(m, e, n)
        c2 = pow(a * m + b, e, n)
        fmt = self.rng.randrange(5)
        if fmt == 0:
            data = f"n = {n}\nc1 = {c1}\nc2 = {c2}\nA = {a}\nB = {b}\n".encode()
        elif fmt == 1:
            data = f"n={n}\nc1={c1}\nc2={c2}\na={a}\nb={b}\n".encode()
        elif fmt == 2:
            data = f"n = 0x{n:x}\nc1 = 0x{c1:x}\nc2 = 0x{c2:x}\na = {a}\nb = {b}\n".encode()
        elif fmt == 3:
            data = (f"c1 = {c1}\nc2 = {c2}\nn = {n}\n"
                    f"a = {a} b = {b}\n").encode()
        else:
            data = f"n = {n}\nc1 = {c1}\nc2 = {c2}\nA = {a}\nB = {b}\n".encode()
        return "fr", data, f

    def wants_hash(self):
        f = self.flag()
        pw = self.rng.choice([b"password", b"letmein", b"123456", b"qwerty"])
        algo = self.rng.choice(["md5", "sha1", "sha256"])
        hl = hashlib.new(algo, pw).hexdigest()
        key = hl.encode()
        ct = bytes(f[i] ^ key[i % len(key)] for i in range(len(f))).hex()
        fmt = self.rng.randrange(5)
        if fmt == 0:
            data = f"{hl}\n{ct}\n".encode()
        elif fmt == 1:
            data = f"hash = {hl}\nct = {ct}\n".encode()
        elif fmt == 2:
            data = f"{algo} = {hl}\nciphertext: {ct}\n".encode()
        elif fmt == 3:
            data = f"hash: {hl}\nenc: {ct}\n".encode()
        else:
            data = f"{hl}:{ct}\n".encode()
        return "hash", data, f

    def wants_sephex(self):
        f = self.flag()
        k = self.rng.randrange(1, 256)
        raw = bytes(b ^ k for b in f)
        fmt = self.rng.randrange(5)
        if fmt == 0:
            data = " ".join(f"{b:02x}" for b in raw).encode()
        elif fmt == 1:
            data = "\n".join(f"{b:02x}" for b in raw).encode()
        elif fmt == 2:
            data = ",".join(f"0x{b:x}" for b in raw).encode()
        elif fmt == 3:
            data = ":".join(f"{b:02X}" for b in raw).encode()
        else:
            data = ("bytes: " + " ".join(f"{b:02x}" for b in raw)).encode()
        return "sephex", data, f


def run_case(data):
    Path("tm.txt").write_bytes(data)
    r = subprocess.run([sys.executable, "autocrypt.py", "tm.txt",
                        "--timeout", "15", "--json"],
                       capture_output=True, text=True, timeout=40)
    if "AUTO_DEBUG_FAM" in __import__("os").environ:
        print("[famdbg] rc", r.returncode, "stdout:", repr(r.stdout[:160]), file=sys.stderr)
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception as e:
        if "AUTO_DEBUG_FAM" in __import__("os").environ:
            print("[famdbg] PARSE EXC", repr(e), file=sys.stderr)
        out = []
    return out


def family(name, builder, seed):
    g = Gen(seed)
    passed, fails = 0, []
    for i in range(10):
        tag, data, flag = builder(g)
        t0 = time.time()
        out = run_case(data)
        wall = time.time() - t0
        want = flag.decode()
        rank = next((k for k, x in enumerate(out)
                     if want.lower() in x["plaintext"].lower()), None)
        if rank == 0 and wall < 3:
            passed += 1
        else:
            fails.append((f"{tag}_{i}", rank, wall))
    print(f"{name} seed={seed}: {passed}/10")
    for f_ in fails:
        print(f"   FAIL {f_[0]} rank={f_[1]} wall={f_[2]:.1f}s")
    return passed


NEGATIVES = [
    ("neg_hash_noct", b"hash = 0d107d09f5bbe40cade3de5c71e9e9b7\n"),
    ("neg_hash_labels", b"md5 = 5f4dcc3b5aa765d61d8327deb882cf99\npassword = 123456\n"),
    ("neg_fr_unrelated", b"n = 18346015328240010027\nc1 = 123456789\nc2 = 987654321\nA = 1\nB = 1\n"),
    ("neg_common_nonint", b"n = 77\ne1 = 2\nc1 = 12\ne2 = 351\nc2 = 55\n"),
    ("neg_sephex_short", b"bytes: 1 2 3 4 5 6\n"),
    ("neg_hex_words", b"dead beef cafe 1234 ab cd ef 12 34 56 78 90 11 22 33 44 55 66\n"),
]


def negatives():
    bad = 0
    for name, data in NEGATIVES:
        out = run_case(data)
        for x in out:
            if "academy{" in x["plaintext"]:
                print(f"FP {name}: {x['plaintext'][:40]!r}")
                bad += 1
    print(f"negatives: {bad} false positives (target 0)")
    return bad


def main():
    total = 0
    total += family("common-modulus", Gen.wants_common, 20270730)
    total += family("franklin-reiter", Gen.wants_fr, 20270731)
    total += family("hash-crack", Gen.wants_hash, 20270732)
    total += family("sep-hex", Gen.wants_sephex, 20270733)
    neg = negatives()
    print(f"TOTAL {total}/40, FP {neg}")


if __name__ == "__main__":
    main()
