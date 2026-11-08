#!/usr/bin/env python3
"""E3a realistic CTF fixture builder (synthetic flags).

Writes fixtures/e3/cNN_challenge.py + cNN_output.txt for 15 pairs. The flag
is NEVER stored in any file: real challenges read it from flag.txt (not
provided). A final assertion fails generation if the flag or any of its
base64 / hex / reversed encodings appear in a pair file. Keys that real
challenges expose (Vigenere key, XOR key, Caesar shift, LFSR taps) are kept.
Seeds are fixed (20270710); .py files may import libraries that are NOT
installed (Crypto, gmpy2) - they are never executed.
"""
import base64
import hashlib
import os
import random
from pathlib import Path

E3_TMP = Path(__file__).resolve().parent / "fixtures" / "e3"


def w3(name, data):
    p = E3_TMP / name
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    print("wrote", p, len(data), "bytes")


def rot13(s):
    t = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
    return s.translate(t)


def caesar(s, k):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(s, key):
    out, i = [], 0
    for ch in s:
        if ch.isalpha():
            k = ord(key[i % len(key)]) - 97
            b = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - b + k) % 26 + b))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def xor_bytes(b, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(b))


def randprime(rng, bits):
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
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


FLAGS = {
    "c01": b"academy{b64_hex_rot13_l4y3r}",
    "c02": b"academy{caesar_7_hint}",
    "c03": b"academy{vigenere_key_k3y}",
    "c04": b"academy{repeat_xor_h4ck_k3y}",
    "c05": b"academy{rsa_small_e3_unlabeled}",
    "c06": b"academy{rsa_p_q_printed}",
    "c07": b"academy{hash_key_xor_sha256}",
    "c08": b"academy{reverse_b64_caesar_cust0m}",
    "c09": b"academy{common_modulus_rsa}",
    "c10": b"academy{hastad_broadcast_e3}",
    "c11": b"academy{franklin_reiter_related}",
    "c12": b"academy{dh_shared_secret_xor}",
    "c13": b"academy{hash_crack_weak_pw}",
    "c14": b"academy{lfsr_keystream_crib}",
    "c15": b"academy{single_byte_xor_bin}",
}


def build():
    os.makedirs(E3_TMP, exist_ok=True)
    rng = random.Random(20270710)

    def add(name, py, out):
        w3(f"{name}_challenge.py", py)
        w3(f"{name}_output.txt", out)

    # c01 base64 -> hex -> rot13
    f = FLAGS["c01"]
    ct = rot13(base64.b64encode(f).hex())
    add("c01", '''import base64
flag = open('flag.txt','rb').read().strip()
first = base64.b64encode(flag).decode()
second = first.encode().hex()
def rot13(s):
    return s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
print(f"ciphertext: {rot13(second)}")
''', f"ciphertext: {ct}\n")

    # c02 Caesar shift 7
    ct = caesar(FLAGS["c02"].decode(), 7)
    add("c02", '''shift = 7
flag = open('flag.txt','rb').read().strip()
enc = ''.join(
    chr((ord(c) - 97 + shift) % 26 + 97) if 'a' <= c <= 'z' else
    chr((ord(c) - 65 + shift) % 26 + 65) if 'A' <= c <= 'Z' else c
    for c in flag.decode())
print('encrypted:', enc)
''', f"encrypted: {ct}\n")

    # c03 Vigenere key visible
    key = "crypto"
    ct = vigenere(FLAGS["c03"].decode(), key)
    add("c03", '''key = 'crypto'
flag = open('flag.txt','rb').read().strip()
def vig(t, k):
    out, i = [], 0
    for c in t:
        if c.isalpha():
            ki = ord(k[i % len(k)]) - 97
            b = 65 if c.isupper() else 97
            out.append(chr((ord(c) - b + ki) % 26 + b))
            i += 1
        else:
            out.append(c)
    return ''.join(out)
print('ct =', vig(flag.decode(), key))
''', f"ct = {ct}\n")

    # c04 repeating-key XOR, key visible
    key = b"h4ck"
    ct = xor_bytes(FLAGS["c04"], key).hex()
    add("c04", '''key = b'h4ck'
flag = open('flag.txt','rb').read().strip()
ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(flag))
print('ct =', ct.hex())
''', f"ct = {ct}\n")

    # c05 RSA small e=3 unlabeled
    f = FLAGS["c05"]
    m = int.from_bytes(f, "big")
    p, q = randprime(rng, 512), randprime(rng, 512)
    n = p * q
    e = 3
    assert m ** e < n
    c = m ** e
    add("c05", '''from Crypto.Util.number import bytes_to_long, getPrime
flag = open('flag.txt','rb').read().strip()
p = getPrime(512); q = getPrime(512)
n = p * q
e = 3
m = bytes_to_long(flag)
c = pow(m, e, n)
print(n)
print(e)
print(c)
''', f"{n}\n{e}\n{c}\n")

    # c06 RSA p,q,e,c labeled, no n
    f = FLAGS["c06"]
    m = int.from_bytes(f, "big")
    p, q = randprime(rng, 256), randprime(rng, 256)
    n = p * q
    e = 65537
    c = pow(m, e, n)
    add("c06", '''import gmpy2
flag = open('flag.txt','rb').read().strip()
p = gmpy2.next_prime(2**255 + 12345)
q = gmpy2.next_prime(2**255 + 67890)
e = 65537
m = int.from_bytes(flag, 'big')
c = pow(m, e, p * q)
print('p =', p)
print('q =', q)
print('e =', e)
print('c =', c)
''', f"p = {p}\nq = {q}\ne = {e}\nc = {c}\n")

    # c07 hash-derived key XOR (sha256(secret))
    f = FLAGS["c07"]
    key = hashlib.sha256(b"pr0t0n-secret").digest()
    ct = xor_bytes(f, key).hex()
    add("c07", '''import hashlib
secret = b'pr0t0n-secret'
flag = open('flag.txt','rb').read().strip()
key = hashlib.sha256(secret).digest()
ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(flag))
print(ct.hex())
''', f"{ct}\n")

    # c08 reverse -> base64 -> caesar5
    f = FLAGS["c08"]
    ct = caesar(base64.b64encode(f.decode()[::-1].encode()).decode(), 5)
    add("c08", '''import base64
flag = open('flag.txt','rb').read().strip()
rev = flag.decode()[::-1]
b64 = base64.b64encode(rev.encode()).decode()
def caesar5(s):
    return ''.join(
        chr((ord(c) - 97 + 5) % 26 + 97) if 'a' <= c <= 'z' else
        chr((ord(c) - 65 + 5) % 26 + 65) if 'A' <= c <= 'Z' else c
        for c in s)
print('ct =', caesar5(b64))
''', f"ct = {ct}\n")

    # c09 common-modulus RSA
    f = FLAGS["c09"]
    m = int.from_bytes(f, "big")
    p, q = randprime(rng, 512), randprime(rng, 512)
    n = p * q
    e1, e2 = 65537, 17
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    add("c09", '''flag = open('flag.txt','rb').read().strip()
m = int.from_bytes(flag, 'big')
# same modulus reused for two exponents
print('n =', n)
print('e1 =', 65537)
print('c1 =', c1)
print('e2 =', 17)
print('c2 =', c2)
''', f"n = {n}\ne1 = {e1}\nc1 = {c1}\ne2 = {e2}\nc2 = {c2}\n")

    # c10 Hastad broadcast e=3
    f = FLAGS["c10"]
    m = int.from_bytes(f, "big")
    e = 3
    mods = []
    for _ in range(3):
        p, q = randprime(rng, 512), randprime(rng, 512)
        mods.append((p * q, pow(m, e, p * q)))
    lines = [f"e = {e}"]
    for i, (ni, ci) in enumerate(mods, 1):
        lines.append(f"n{i} = {ni}")
        lines.append(f"c{i} = {ci}")
    add("c10", '''flag = open('flag.txt','rb').read().strip()
m = int.from_bytes(flag, 'big')
e = 3
# broadcast the same message to three recipients
print('e =', e)
print('n1 =', n1)
print('c1 =', c1)
print('n2 =', n2)
print('c2 =', c2)
print('n3 =', n3)
print('c3 =', c3)
''', "\n".join(lines) + "\n")

    # c11 Franklin-Reiter related messages
    f = FLAGS["c11"]
    m = int.from_bytes(f, "big")
    p, q = randprime(rng, 512), randprime(rng, 512)
    n = p * q
    c1 = pow(m, 3, n)
    c2 = pow(m + 1, 3, n)
    add("c11", '''flag = open('flag.txt','rb').read().strip()
m = int.from_bytes(flag, 'big')
c1 = pow(m, 3, n)
c2 = pow(m + 1, 3, n)
print('n =', n)
print('c1 =', c1)
print('c2 =', c2)
print('diff = 1')
''', f"n = {n}\nc1 = {c1}\nc2 = {c2}\ndiff = 1\n")

    # c12 DH shared secret -> XOR key
    f = FLAGS["c12"]
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    g = 2
    a = 123456789987654321
    b = 987654321123456789
    A = pow(g, a, p)
    B = pow(g, b, p)
    K = pow(A, b, p)
    key = hashlib.sha256(str(K).encode()).digest()
    ct = xor_bytes(f, key).hex()
    add("c12", '''p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
g = 2
flag = open('flag.txt','rb').read().strip()
A = pow(g, 123456789987654321, p)
B = pow(g, 987654321123456789, p)
shared = pow(A, 987654321123456789, p)
key = hashlib.sha256(str(shared).encode()).digest()
ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(flag))
print('p =', p)
print('g =', g)
print('A =', A)
print('B =', B)
print('ct =', ct.hex())
''', f"p = {p}\ng = {g}\nA = {A}\nB = {B}\nct = {ct}\n")

    # c13 hash cracking: md5 of weak password then XOR
    f = FLAGS["c13"]
    pw = b"letmein"
    h = hashlib.md5(pw).hexdigest().encode()
    ct = xor_bytes(f, h).hex()
    add("c13", '''import hashlib
flag = open('flag.txt','rb').read().strip()
password = b'letmein'
h = hashlib.md5(password).hexdigest().encode()
ct = bytes(c ^ h[i % len(h)] for i, c in enumerate(flag))
print('hash =', hashlib.md5(password).hexdigest())
print('ct =', ct.hex())
''', f"hash = {hashlib.md5(pw).hexdigest()}\nct = {ct}\n")

    # c14 LFSR keystream with known-prefix crib
    f = FLAGS["c14"]
    taps = (15, 13, 12, 10)
    seed = 0xBEEF

    def step(state):
        bit = 0
        for t in taps:
            bit ^= (state >> t) & 1
        return ((state << 1) | bit) & 0xFFFF

    ks = []
    st = seed
    for _ in range(len(f)):
        st = step(st)
        ks.append(st & 0xFF)
    ct = bytes(f[i] ^ ks[i] for i in range(len(f))).hex()
    add("c14", '''seed = 0xBEEF
taps = (15, 13, 12, 10)
flag = open('flag.txt','rb').read().strip()
def step(state):
    bit = 0
    for t in taps:
        bit ^= (state >> t) & 1
    return ((state << 1) | bit) & 0xFFFF
state = seed
ks = bytearray()
for _ in range(len(flag)):
    state = step(state)
    ks.append(state & 0xFF)
ct = bytes(c ^ ks[i] for i, c in enumerate(flag))
print('keystream_hex =', ks.hex())
print('ct =', ct.hex())
''', f"keystream_hex = {bytes(ks).hex()}\nct = {ct}\n")

    # c15 single-byte XOR in a binary-ish file
    f = FLAGS["c15"]
    k = 0xA7
    ct = bytes(b ^ k for b in f).hex()
    add("c15", '''flag = open('flag.txt','rb').read().strip()
key = 0xA7
ct = bytes(b ^ key for b in flag)
print('bytes:', ' '.join(f'{b:02x}' for b in ct))
''', f"bytes: {' '.join(f'{b:02x}' for b in bytes.fromhex(ct))}\n")

    # --- assertion: no file contains the flag or its encodings ---
    for name, flag in FLAGS.items():
        variants = [flag, base64.b64encode(flag), flag.hex().encode(),
                    flag[::-1], flag.hex().encode()[::-1],
                    base64.b64encode(flag[::-1]),
                    base64.b64encode(flag).hex().encode()]
        for ext in ("_challenge.py", "_output.txt"):
            p = E3_TMP / f"{name}{ext}"
            data = p.read_bytes()
            for v in variants:
                assert v not in data, f"E3 leak: {name} encoding in {p}"


if __name__ == "__main__":
    build()
