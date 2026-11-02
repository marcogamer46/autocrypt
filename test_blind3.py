#!/usr/bin/env python3
"""E2b2: blind test set 3 - 25 fresh cases, seed 20270630 (blind seed 3)
used while developing the solvers: 20261031 / 20261101). Random prefixes,
random bodies, random keys. Coverage: caesar, rot13, atbash, vigenere, xor
(1-4 byte keys), base64/hex layers (1-4 deep), rail fence, RSA small cases.

Prints only the PASS count and rate. Threshold: < 90% means a real bug.
"""
import base64
import random
import string
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

rng = random.Random(20270630)  # blind seed 3

LEET_WORDS = ["c0de", "fl4g", "s3cr3t", "k3y", "x0r", "l33t", "h4ck",
               "c1ph3r", "r3v", "pwn", "m1sc", "w3b", "n0t", "eng1ish",
               "h3ll0", "w0rld", "t3st", "d4ta", "f1nd", "m4ny", "k3ys",
               "crypt0", "b4se", "h0me", "w4nt"]

ALPHA = string.ascii_letters + string.digits + "_"


def rand_flag(short=False):
    n = rng.randint(2 if short else 4, 5 if short else 10)
    prefix = "".join(rng.choice(ALPHA) for _ in range(n))
    k = rng.randint(1, 2) if short else rng.randint(2, 4)
    body = "_".join(rng.choice(LEET_WORDS) for _ in range(k))
    return prefix + "{" + body + "}"


def caesar(t, k):
    out = []
    for c in t:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def atbash(t):
    return "".join(chr(155 - ord(c)) if c.isupper() else chr(219 - ord(c))
                   if c.islower() else c for c in t)


def vigenere(t, key):
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


def xor_bytes(b, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(b))


def rail(t, r):
    pat = list(range(r)) + list(range(r - 2, 0, -1))
    rows = [[] for _ in range(r)]
    for i, c in enumerate(t):
        rows[pat[i % len(pat)]].append(c)
    return "".join("".join(x) for x in rows)


def small_prime(bits):
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if n > 1 and all(n % d for d in (2, 3, 5, 7, 11, 13, 17, 19, 23,
                                          29, 31, 37, 41, 43, 47)):
            # cheap probable-prime check for tiny sizes
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


def rsa_small_flag():
    # short flag so m fits a small modulus
    return rand_flag(short=True)


def rsa_case(flag):
    m = int.from_bytes(flag.encode(), "big")
    # e = 3 with m^3 < n: exact cube-root recovery (small-e attack)
    n = small_prime(128) * small_prime(128)
    e = 3
    assert m ** e < n
    c = m ** e
    return f"n={n}\ne={e}\nc={c}\n".encode()


def rsa_case_factored(flag):
    m = int.from_bytes(flag.encode(), "big")
    p, q = small_prime(36), small_prime(36)
    n = p * q
    assert m < n
    e = 65537
    c = pow(m, e, n)
    return f"n={n}\ne={e}\nc={c}\n".encode()


def rsa_micro_flag():
    # tiny random flag that fits a ~72-bit modulus (< 9 bytes)
    rn = "".join(rng.choice(string.ascii_lowercase) for _ in range(3))
    return rn + "{a1}"


def run_case(data_bytes):
    Path("tm.txt").write_bytes(data_bytes)
    r = subprocess.run(["python3", "autocrypt.py", "tm.txt",
                        "--timeout", "15", "--json"],
                       capture_output=True, text=True, timeout=40)
    try:
        import json
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception:
        out = []
    return out


cases = []  # (name, data_bytes, expected_flag)

def add(name, data, flag):
    cases.append((name, data, flag))


def build_cases():
    # --- build 25 blind cases ---
    # 1-4: caesar / rot13 / atbash / vigenere
    f = rand_flag(); add("caesar", caesar(f, rng.randint(1, 25)).encode(), f)
    f = rand_flag(); add("rot13", caesar(f, 13).encode(), f)
    f = rand_flag(); add("atbash", atbash(f).encode(), f)
    f = rand_flag(); add("vigenere", vigenere(f, rng.choice(["lemon", "secret", "key", "crypto"])).encode(), f)

    # 5-8: xor keys of length 1..4
    for L in (1, 2, 3, 4):
        f = rand_flag()
        key = bytes(rng.randrange(33, 127) for _ in range(L))
        add(f"xor{L}", xor_bytes(f.encode(), key).hex().encode(), f)

    # 9-14: base64/hex layers, 1..4 deep
    f = rand_flag()
    add("b64", base64.b64encode(f.encode()), f)
    f = rand_flag()
    add("hex", f.encode().hex().encode(), f)
    f = rand_flag()
    add("b64x2", base64.b64encode(base64.b64encode(f.encode())), f)
    f = rand_flag()
    add("hex_b64", base64.b64encode(f.encode().hex().encode()), f)
    f = rand_flag()
    add("b64_hex_b64", base64.b64encode(f.encode().hex().encode().hex().encode()), f)
    f = rand_flag()
    s = f.encode().hex().encode()
    s = base64.b64encode(s)
    s = s.hex().encode()
    s = base64.b64encode(s)
    add("hex4", s, f)

    # 15-18: rail fence rails 2..5
    for r in (2, 3, 4, 5):
        f = rand_flag()
        add(f"rail{r}", rail(f, r).encode(), f)

    # 19-20: RSA small (e=3) and RSA factored small
    f = rsa_small_flag(); add("rsa_small", rsa_case(f), f)
    f = rsa_micro_flag(); add("rsa_factored", rsa_case_factored(f), f)

    # 21-25: layered combos
    f = rand_flag(); add("caesar_b64", base64.b64encode(caesar(f, 7).encode()), f)
    f = rand_flag(); add("vigenere_hex", vigenere(f, "lemon").encode().hex().encode(), f)
    f = rand_flag()
    key = bytes(rng.randrange(33, 127) for _ in range(2))
    add("xor2_b64", base64.b64encode(xor_bytes(f.encode(), key)), f)
    f = rand_flag(); add("atbash_rot13", caesar(atbash(f), 13).encode(), f)
    f = rand_flag(); add("rail3_b64", base64.b64encode(rail(f, 3).encode()), f)
    return cases


def main():
    passed = 0
    details = []
    for name, data, flag in build_cases():
        out = run_case(data)
        rank = next((i for i, x in enumerate(out)
                     if flag.lower() in x["plaintext"].lower()), None)
        if rank == 0:
            passed += 1
        details.append((name, rank, out[0]["chain"][:50] if out else "-",
                        out[0]["plaintext"][:36] if out else "-"))

    total = len(cases)
    rate = 100.0 * passed / total
    print(f"BLIND: {passed}/{total} ({rate:.1f}%)")
    print(f"THRESHOLD: {'OK' if rate >= 90 else 'BELOW 90% - REAL BUG TO INVESTIGATE'}")
    if "--details" in sys.argv:
        for name, rank, chain, top in details:
            print(f"  {name:16} rank={rank} top={chain!r} {top!r}")
    sys.exit(0 if rate >= 90 else 1)


if __name__ == "__main__":
    main()
