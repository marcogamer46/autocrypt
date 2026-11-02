#!/usr/bin/env python3
"""Deterministically regenerate the repo-owned fixtures/ folder.

Seeds are fixed here, so regenerating produces byte-identical fixtures
(required for stable regression tests).
"""
import base64
import io
import math
import random
import struct
import sys
import wave
import os
from pathlib import Path

random.seed(20261101)  # fixed seed: deterministic output across runs

# ---------------- E3a: realistic CTF pairs (synthetic) ----------------
# builder module keeps the flag out of every file; see e3_section.py
from e3_section import build as e3_make
e3_make()

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solvers  # noqa: F401  (loads the full registry; resolves circular imports)
from solvers_pack6 import _enigma_encrypt, _Z85_ALPH
from solvers_pack3 import _BRAILLE
from scoring import assess
import solvers_more as _more
_is_prime = _more._is_prime

TMP = Path(__file__).resolve().parent / "fixtures"
os.makedirs(TMP, exist_ok=True)

def w(name, data, mode="wb"):
    p = TMP / name
    with open(p, mode) as f:
        f.write(data)
    print("wrote", p, len(data), "bytes")

def isprime(n):
    return _is_prime(n)

def randprime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if isprime(n): return n

def int_to_bytes(m):
    n = max(1, (m.bit_length() + 7) // 8)
    return m.to_bytes(n, "big")

def rsa_file(name, msg, e=65537, primes=None, e_even=False):
    p, q = primes or (randprime(384), randprime(384))
    n = p * q
    m = int.from_bytes(msg, "big")
    assert m < n, "message too big"
    c = pow(m, e, n)
    w(name, f"n={n}\ne={e}\nc={c}\n".encode())

# ---------------- message.txt already exists ----------------

# ---------------- rsa_even: even e (e=4) ----------------
rsa_file("rsa_even.txt", b"academy{even_n_rsa}", e=4, e_even=True)

# ---------------- LFSR (binary, crib academy{) ----------------
def lfsr_keystream(seed, taps, nbits):
    state = seed
    out = []
    for _ in range(nbits):
        out.append(state & 1)
        bit = 0
        for t in taps:
            bit ^= (state >> t) & 1
        state = ((state >> 1) | (bit << 15)) & 0xFFFF
    return out

plain = b"academy{lfsr_sample_flag}"
bits = lfsr_keystream(0xACE1, (15, 13, 12, 10), len(plain) * 8)
ct = bytes(sum(bits[i*8+j] << (7-j) for j in range(8)) ^ plain[i] for i in range(len(plain)))
w("lfsr_sample.bin", ct)

# ---------------- t.txt: b64( b'...' ) where inner is b64( caesar7(flag) ) ----------------
flag_t = b"academy{caesar_d3cr9pt3d_9948dfa2}"
caesar7 = bytes((b + 7 - 97) % 26 + 97 if 97 <= b <= 122 else b for b in flag_t)
inner = base64.b64encode(caesar7)
lit = b"b'" + inner + b"'"
final = base64.b64encode(lit)
w("t.txt", final)

# ---------------- c1_plain / c1_b64 ----------------
w("c1_plain.txt", b"TTFCTFGGH{c1_plain}")
w("c1_b64.txt", base64.b64encode(b"TTFCTFGGH{c1_b64}"))

# ---------------- z85 ----------------
z85msg = b"academy{z85_works}"
def z85_encode(b):
    out = []
    i = 0
    while i < len(b):
        chunk = b[i:i+4]
        n = len(chunk)
        if n == 4:
            v = int.from_bytes(chunk, "big")
            width = 5
        else:
            v = int.from_bytes(chunk, "big")
            width = n + 1
        s = ""
        for _ in range(width):
            s = _Z85_ALPH[v % 85] + s
            v //= 85
        out.append(s)
        i += 4
    return "".join(out)
w("z85_sample.txt", z85_encode(z85msg).encode())

# ---------------- custom alphabet base ----------------
cmsg = b"Academy{custom_base_works}"
import string as _string
allchars = list(_string.printable[:95])
random.Random(7).shuffle(allchars)
alph = "".join(allchars)
B = len(alph)
v = 0
for ch in cmsg:
    v = v * B + alph.index(chr(ch))
data = ""
while v:
    data = alph[v % B] + data
    v //= B
w("custombase_sample.txt", f"alphabet={alph}\ndata={data}\n".encode())

# ---------------- CRT ----------------
crt_flag = b"academy{crt}"
crt_v = int.from_bytes(crt_flag, "big")
mods = [randprime(40) for _ in range(9)]
lines = [f"x = {crt_v % m} mod {m}" for m in mods]
w("crt_sample.txt", ("\n".join(lines) + "\n").encode())

# ---------------- pp1 (3-prime modulus; all p_i-1 smooth -> pm1 splits each) ----------------
def smooth_prime(minbits, maxbits):
    rng = random.Random(20261101 + minbits + maxbits)
    for _ in range(300):
        m2 = rng.randint(4, 8)
        small = [2] * m2 + [3] * rng.randint(2, 5) + [5] * rng.randint(1, 3) \
                + [7] * rng.randint(1, 2) + rng.sample([11, 13, 17, 19, 23, 29, 31], rng.randint(4, 6))
        prod = 1
        for f in small:
            prod *= f
        if prod.bit_length() > minbits - 2:
            continue
        # keep every prime power of p-1 <= 200000 so the p-1 stage (B=200000)
        # splits this prime instantly; 2^(m2+k) must stay <= 2^17.
        for k in range(1, 18 - m2):
            p = prod * 2**k + 1
            if minbits <= p.bit_length() <= maxbits and isprime(p):
                return p
    raise RuntimeError("smooth_prime: no prime found")
pp1_p = smooth_prime(42, 52)
pp1_q = smooth_prime(42, 52)
pp1_r = smooth_prime(42, 52)
pp1_n = pp1_p * pp1_q * pp1_r
pp1_e = 65537
pp1_phi = (pp1_p - 1) * (pp1_q - 1) * (pp1_r - 1)
pp1_m = int.from_bytes(b"academy{pp1_ok}", "big")
assert pp1_m < pp1_n
pp1_c = pow(pp1_m, pp1_e, pp1_n)
w("pp1_rsa.txt", f"n={pp1_n}\ne={pp1_e}\nc={pp1_c}\n".encode())

# ---------------- EC DLP ----------------
def ec_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q:
        lam = (3*x1*x1 + a) * pow(2*y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, P, a, p):
    R = None
    Q = P
    while k:
        if k & 1: R = ec_add(R, Q, a, p)
        Q = ec_add(Q, Q, a, p)
        k >>= 1
    return R

ec_p = 17
ec_a, ec_b = 2, 2
ec_G = (5, 1)      # order 19 on y^2=x^3+2x+2 mod 17
ec_n = 19
ec_k = 7
ec_Q = ec_mul(ec_k, ec_G, ec_a, ec_p)
w("ec_sample.txt", f"p={ec_p}\nn={ec_n}\na={ec_a}\nb={ec_b}\ngx={ec_G[0]}\ngy={ec_G[1]}\nqx={ec_Q[0]}\nqy={ec_Q[1]}\n".encode())

# ---------------- ECDSA nonce reuse ----------------
ecdsa_n = 101
ecdsa_k = 23
ecdsa_d = 37
ecdsa_r = 55
z1, z2 = 33, 71
s1 = pow(ecdsa_k, -1, ecdsa_n) * (z1 + ecdsa_r * ecdsa_d) % ecdsa_n
s2 = pow(ecdsa_k, -1, ecdsa_n) * (z2 + ecdsa_r * ecdsa_d) % ecdsa_n
ecdsa_Q = ec_mul(ecdsa_d, ec_G, ec_a, ec_p)
w("ecdsa_reuse.txt", f"p={ec_p}\nn={ecdsa_n}\na={ec_a}\nb={ec_b}\ngx={ec_G[0]}\ngy={ec_G[1]}\nqx={ecdsa_Q[0]}\nqy={ecdsa_Q[1]}\nr={ecdsa_r}\ns1={s1}\ns2={s2}\nz1={z1}\nz2={z2}\n".encode())

# ---------------- DSA nonce reuse ----------------
dsa_q = 103
dsa_k = 29
dsa_d = 41
dsa_r = 67
h1, h2 = 10, 50
dsa_s1 = pow(dsa_k, -1, dsa_q) * (h1 + dsa_r * dsa_d) % dsa_q
dsa_s2 = pow(dsa_k, -1, dsa_q) * (h2 + dsa_r * dsa_d) % dsa_q
w("dsa_sample.txt", f"q={dsa_q}\nr={dsa_r}\ns1={dsa_s1}\ns2={dsa_s2}\nh1={h1}\nh2={h2}\n".encode())

# ---------------- shared prime ----------------
sp_p = randprime(384)
sp_q1 = randprime(384)
sp_q2 = randprime(384)
sp_n1 = sp_p * sp_q1
sp_n2 = sp_p * sp_q2
sp_e = 65537
sp_m = int.from_bytes(b"academy{shared_prime}", "big")
sp_c1 = pow(sp_m, sp_e, sp_n1)
sp_c2 = pow(sp_m, sp_e, sp_n2)
w("sharedprime_sample.txt", f"n1={sp_n1}\nn2={sp_n2}\nc1={sp_c1}\nc2={sp_c2}\n".encode())

# ---------------- dp/dq ----------------
dp_p = randprime(384)
dp_q = randprime(384)
dp_n = dp_p * dp_q
dp_e = 65537
dp_phi = (dp_p-1)*(dp_q-1)
dp_d = pow(dp_e, -1, dp_phi)
dp_m = int.from_bytes(b"academy{dp_dq}", "big")
dp_c = pow(dp_m, dp_e, dp_n)
w("dpdq_sample.txt", f"p={dp_p}\nq={dp_q}\ndp={dp_d % (dp_p-1)}\ndq={dp_d % (dp_q-1)}\nc={dp_c}\n".encode())

# ---------------- known p+q ----------------
pq_p = randprime(384)
pq_q = randprime(384)
pq_n = pq_p * pq_q
pq_e = 65537
pq_m = int.from_bytes(b"academy{pqsum}", "big")
pq_c = pow(pq_m, pq_e, pq_n)
w("pqsum_sample.txt", f"n={pq_n}\ne={pq_e}\nc={pq_c}\ns={pq_p + pq_q}\n".encode())

# ---------------- Franklin-Reiter (labeled + unlabeled) ----------------
fr_p = randprime(384)
fr_q = randprime(384)
fr_N = fr_p * fr_q
fr_e = 3
fr_m1 = int.from_bytes(b"Franklin-Reiter message one", "big")
fr_diff = 424242
fr_m2 = fr_m1 + fr_diff
fr_c1 = pow(fr_m1, fr_e, fr_N)
fr_c2 = pow(fr_m2, fr_e, fr_N)
w("fr_labeled.txt", f"N={fr_N}\nc1={fr_c1}\nc2={fr_c2}\ndiff={fr_diff}\n".encode())
w("fr_unlabeled.txt", f"{fr_c1} {fr_c2} {fr_diff} {fr_N}\n".encode())

# ---------------- LCG ----------------
lcg_a = 1103515245
lcg_c = 12345
lcg_m = 2**31
lcg_state = 987654321
lcg_outs = []
for _ in range(8):
    lcg_state = (lcg_a * lcg_state + lcg_c) % lcg_m
    lcg_outs.append(lcg_state)
w("lcg_sample.txt", ("\n".join(map(str, lcg_outs)) + "\n").encode())

# ---------------- MT19937 ----------------
MT_N = 624
MT_M = 397
MT_MATRIX = 0x9908b0df
MT_UPPER = 0x80000000
MT_LOWER = 0x7fffffff

def mt_init(seed):
    mt = [0]*(MT_N+1)
    mt[0] = seed
    for i in range(1, MT_N):
        mt[i] = (1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i) & 0xffffffff
    mt[MT_N] = MT_N
    return mt

def mt_next(mt):
    idx = mt[MT_N]
    if idx >= MT_N:
        for i in range(MT_N):
            y = (mt[i] & MT_UPPER) | (mt[(i+1) % MT_N] & MT_LOWER)
            mt[i] = mt[(i + MT_M) % MT_N] ^ (y >> 1)
            if y & 1:
                mt[i] ^= MT_MATRIX
        idx = 0
    y = mt[idx]
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    mt[MT_N] = idx + 1
    return y & 0xffffffff

mt = mt_init(20261031)
mt_outs = [mt_next(mt) for _ in range(624)]
w("mt_sample.txt", ("\n".join(map(str, mt_outs)) + "\n").encode())

# ---------------- DH DLP (smooth p-1) ----------------
def dh_prime(minbits):
    while True:
        small = [2,2,2,3,3,5,5,7,11,13,17,19,23,29,31,37,41,43,47]
        prod = 1
        for f in small:
            prod *= f
        for k in range(1, 30):
            p = prod * 2**k + 1
            if p.bit_length() >= minbits and isprime(p):
                return p

def primitive_root(p):
    facs = set()
    m = p - 1
    d = 2
    while d * d <= m:
        if m % d == 0:
            facs.add(d)
            while m % d == 0:
                m //= d
        d += 1
    if m > 1:
        facs.add(m)
    for g in range(2, 100):
        if all(pow(g, (p - 1) // q, p) != 1 for q in facs):
            return g
    return None

dh_p = dh_prime(64)
dh_g = primitive_root(dh_p)
dh_a = 12345
dh_b = 67890
dh_A = pow(dh_g, dh_a, dh_p)
dh_B = pow(dh_g, dh_b, dh_p)
w("dh_dlp_sample.txt", f"g={dh_g}\np={dh_p}\nA={dh_A}\nB={dh_B}\n".encode())

# ---------------- RC4 ----------------
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

rc4_key = b"autocrypt"
rc4_ct = rc4(rc4_key, b"academy{rc4_key_works}")
w("rc4_sample.txt", f"key={rc4_key.decode()}\n{rc4_ct.hex()}\n".encode())

# ---------------- hash ----------------
import hashlib
w("hash_sample.txt", hashlib.md5(b"autocrypt").hexdigest().encode() + b"\n")

# ---------------- RSA even-e (separate fixture) ----------------
# e=4; close primes so Fermat factorization in _factor succeeds instantly, and
# m^4 > n so no trivial exact integer root (forces the even-e square-root path).
def close_primes(bits, gap):
    while True:
        p = randprime(bits)
        q = p + gap
        if q % 2 == 0:
            q += 1
        if isprime(q):
            return p, q
even_p, even_q = close_primes(160, 200)
even_n = even_p * even_q
even_m = int.from_bytes(b"academy{even_e_ok}", "big")
assert even_m < even_n
assert even_m ** 4 > even_n
even_c = pow(even_m, 4, even_n)
w("even_e_sample.txt", f"n={even_n}\ne=4\nc={even_c}\n".encode())

# ---------------- dna / twosym / braille / b32hex ----------------
enc_msg = b"academy{extra_encodings}"
# DNA 2-bit (A=00,C=01,G=10,T=11)
dna_bits = "".join(f"{b:08b}" for b in enc_msg)
dna_map = {"00": "A", "01": "C", "10": "G", "11": "T"}
dna = "".join(dna_map[dna_bits[i:i+2]] for i in range(0, len(dna_bits), 2))
w("dna_sample.txt", dna.encode())
# two-symbol
two_bits = "".join(f"{b:08b}" for b in enc_msg)
two = "".join("." if b == "0" else "#" for b in two_bits)
w("twosym_sample.txt", two.encode())
# braille
braille = "".join(chr(0x2800 + (c - 32)) for c in enc_msg)
w("braille_sample.txt", braille.encode("utf-8"))
# base32hex
b32hex = base64.b32hexencode(enc_msg)
w("b32hex_sample.txt", b32hex)

# ---------------- LSB PNG (plane 1, R channel) ----------------
from PIL import Image
lsb_flag = b"academy{lsb_plane1}"
N = 48
img = Image.new("RGB", (N, N), (120, 130, 140))
px = img.load()
bits = "".join(f"{b:08b}" for b in lsb_flag)
for i, b in enumerate(bits):
    r, c = divmod(i, N)
    if i >= len(bits):
        break
    pr, pg, pb = px[c, r]
    bit = int(b)
    px[c, r] = ((pr & ~2) | (bit << 1), pg, pb)
img.save(os.path.join(TMP, "lsb_plane1.png"))

# ---------------- WAV LSB (plane 2, channel 0) ----------------
wav_flag = b"academy{wav_lsb_plane2}"
wav_bits = "".join(f"{b:08b}" for b in wav_flag)
rate = 8000
nsamples = len(wav_bits) * 2 + 32
buf = io.BytesIO()
with wave.open(buf, "wb") as wf:
    wf.setnchannels(1)
    wf.setsampwidth(2)
    wf.setframerate(rate)
    data = bytearray()
    for i in range(nsamples):
        v = 4000 + (i * 37) % 4000
        if i < len(wav_bits):
            bit = int(wav_bits[i])
            v = (v & ~4) | (bit << 2)
        data += struct.pack("<h", v)
    wf.writeframes(bytes(data))
w("wav_sample.wav", buf.getvalue())

# ---------------- Enigma direct ----------------
enigma_pt = "THEQUICKBROWNFOXZUMPSOVERTHELAZYDOG"
rotors = ["I", "II", "III"]
rings = [0, 0, 0]
positions = [0, 1, 2]   # AAA -> positions=ABC
reflector = "B"
plugboard = []
enigma_ct = _enigma_encrypt(enigma_pt, rotors, rings, positions, reflector, plugboard)
w("enigma_direct.txt", (f"rotors={' '.join(rotors)}\npositions=ABC\nreflector=B\n"
                        f"{enigma_ct}\n").encode())

# ---------------- DLP smooth-composite fixtures ----------------
DLP_TABLE = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
             59, 61, 67, 71, 73, 79, 83, 89, 97]
_DLP_PRIMES_ODD = [p for p in range(3, 6000, 2) if _is_prime(p)]

def _randprime_bits(bits, rng):
    for _ in range(2000):
        x = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(x):
            return x
    return None

def _dlp_smooth_prime(bits, rng):
    """Same structure as fixtures/real_dlp/gen.py: m smooth (distinct odd
    primes x2) times two mid-size primes, then +1 prime."""
    for _ in range(20000):
        m = 2
        used = set()
        while m.bit_length() < bits - 44:
            f = rng.choice(_DLP_PRIMES_ODD)
            if f not in used:
                used.add(f)
                m *= f
        gap = bits - m.bit_length()
        r1 = _randprime_bits(gap // 2, rng)
        r2 = _randprime_bits(gap - gap // 2, rng)
        if not r1 or not r2:
            continue
        p = m * r1 * r2 + 1
        if p.bit_length() == bits and _is_prime(p):
            return p
    raise RuntimeError("dlp smooth prime failed")

def _dlp_safe_prime(bits, rng):
    # safety-prime-like: (p-1)/2 prime, NOT smooth
    while True:
        q = randprime(bits - 1)
        p = 2 * q + 1
        if isprime(p):
            return p

def make_dlp_fixture(name, bits, g, seed, flag, negative=False):
    rng = random.Random(seed)
    if negative:
        p = _dlp_safe_prime(bits, rng)
        q = _dlp_safe_prime(bits, rng)
    else:
        p = _dlp_smooth_prime(bits, rng)
        q = _dlp_smooth_prime(bits, rng)
    n = p * q
    m = int.from_bytes(flag, "big")
    c = pow(g, m, n)
    if name.endswith("_dec"):
        body = f"n={n}\nc={c}\ng={g}\ndlp_secret=1\n"
    else:
        body = f"n={format(n, 'x')}\nc={format(c, 'x')}\ng={g}\ndlp_secret=1\n"
    w(name + ".txt", body.encode())

dlp_rng = random.Random(20270310)
make_dlp_fixture("dlp512", 512, 3, 20270310, b"academy{dlp512_smooth}")
make_dlp_fixture("dlp1024", 1024, 3, 20270311, b"academy{dlp1024_smooth}")
make_dlp_fixture("dlp_dec_g2", 512, 2, 20270312, b"academy{dlp_dec_g2}",)
make_dlp_fixture("dlp_neg_safe", 1024, 3, 20270313, b"academy{dlp_neg}", negative=True)

# real DLP pair: copied into fixtures/real_dlp (static only)
_real_dlp = Path(__file__).resolve().parent / "fixtures" / "real_dlp"
_real_dlp.mkdir(parents=True, exist_ok=True)
_root_gen = Path("/home/chillinmalware/Documents/autocrypt/gen.py")
if _root_gen.exists():
    (_real_dlp / "gen.py").write_bytes(_root_gen.read_bytes())
    (_real_dlp / "output.txt").write_bytes(
        (Path("/home/chillinmalware/Documents/autocrypt/output.txt")).read_bytes())

print("\nALL FIXTURES REGENERATED")
