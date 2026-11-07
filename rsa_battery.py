#!/usr/bin/env python3
"""Generate raw RSA challenge files across attack classes and run autocrypt on each.

The generated files contain only the raw number-theoretic parameters (n/e/c
and, for hint-style challenges, p/q) — never the plaintext flag. autocrypt must
recover each flag. Expected flags are recorded here purely for verification.
"""
import os, random, math, subprocess, sys, tempfile, shutil

random.seed(20261106)

# ---------- small helpers ----------
def is_prime(n):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d, s = n-1, 0
    while d % 2 == 0: d//=2; s+=1
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        if a >= n: continue
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = x*x % n
            if x == n-1: break
        else: return False
    return True

def next_prime(n):
    n |= 1
    while not is_prime(n): n += 2
    return n

def rand_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(n): return n

def flag_int(tag):
    return int.from_bytes(f"academy{{rsa_{tag}}}".encode(), "big")

def smooth_prime(bits):
    """prime p with p-1 B-smooth (small primes only).

    Bounded retry: build v from random exponents of small primes so that
    v+1 is prime with exactly ``bits`` bits. Each attempt is cheap; the
    expected number of attempts is ~ln(2^bits), so this terminates in
    seconds, not forever (the old loop multiplied one small prime at a time
    and never gave up when it missed the exact bit length / primality).
    """
    small = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71]
    limit = 200000
    for _ in range(limit):
        v = 1
        # multiply random small primes until v is within a couple bits of target
        while v.bit_length() < bits - 2:
            v *= random.choice(small)
        # allow small overshoot; then check p = v+1
        if v.bit_length() > bits + 2:
            continue
        p = v + 1
        if p.bit_length() == bits and is_prime(p):
            return p
    raise RuntimeError(f"no smooth prime found for bits={bits}")

def write(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

# ---------- build cases ----------
def build_cases(outdir):
    cases = []

    def add(name, lines, expected):
        cases.append((name, os.path.join(outdir, name + ".txt"), expected))
        write(os.path.join(outdir, name + ".txt"), lines)

    # 1 baby_pq: p,q given
    p, q = rand_prime(512), rand_prime(512)
    n, e = p*q, 65537
    m = flag_int("baby_pq"); c = pow(m, e, n)
    add("baby_pq", [f"p = {p}", f"q = {q}", f"n = {n}", f"e = {e}", f"c = {c}"],
        "academy{rsa_baby_pq}")

    # 2 small_e_overflow: reduced m^3, m^3 > n
    e = 3
    m = flag_int("small_e_overflow")
    p, q = rand_prime(340), rand_prime(340)
    n = p*q  # ~680 bits < m^3
    c = pow(m, e, n)
    add("small_e_overflow", [f"n = {n}", f"e = {e}", f"c = {c}"],
        "academy{rsa_small_e_overflow}")

    # 3 small_e_exact: unreduced c = m^3, no modulus
    e = 3
    m = flag_int("small_e_exact")
    c = m**3
    add("small_e_exact", [f"e = {e}", f"c = {c}"], "academy{rsa_small_e_exact}")

    # 4 wiener: small d
    p, q = rand_prime(256), rand_prime(256)
    n = p*q; phi = (p-1)*(q-1)
    d = random.getrandbits(120) | 1
    e = pow(d, -1, phi)
    m = flag_int("wiener"); c = pow(m, e, n)
    add("wiener", [f"n = {n}", f"e = {e}", f"c = {c}"], "academy{rsa_wiener}")

    # 5 pm1_smooth: p-1 B-smooth
    p = smooth_prime(200); q = rand_prime(200)
    n = p*q; e = 65537
    m = flag_int("pm1_smooth"); c = pow(m, e, n)
    add("pm1_smooth", [f"n = {n}", f"e = {e}", f"c = {c}"],
        "academy{rsa_pm1_smooth}")

    # 6 fermat_close: close primes
    p = rand_prime(384)
    q = next_prime(p + random.randint(2, 1 << 18))
    n = p*q; e = 65537
    m = flag_int("fermat_close"); c = pow(m, e, n)
    add("fermat_close", [f"n = {n}", f"e = {e}", f"c = {c}"],
        "academy{rsa_fermat_close}")

    # 7 common_modulus
    p, q = rand_prime(384), rand_prime(384)
    n = p*q
    e1, e2 = 3, 5
    m = flag_int("common_modulus")
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    add("common_modulus", [f"n = {n}", f"e1 = {e1}", f"c1 = {c1}",
                            f"e2 = {e2}", f"c2 = {c2}"],
        "academy{rsa_common_modulus}")

    # 8 hastad broadcast, e=3, three moduli
    e = 3
    m = flag_int("hastad")
    lines = [f"e = {e}"]
    for i in range(3):
        p, q = rand_prime(256), rand_prime(256)
        n = p*q
        lines.append(f"n{i+1} = {n}")
        lines.append(f"c{i+1} = {pow(m, e, n)}")
    add("hastad", lines, "academy{rsa_hastad}")

    # 9 shared_prime: two moduli share p
    p = rand_prime(512)
    q1, q2 = rand_prime(512), rand_prime(512)
    n1, n2 = p*q1, p*q2
    e = 65537
    m = flag_int("shared_prime")
    c1, c2 = pow(m, e, n1), pow(m, e, n2)
    add("shared_prime", [f"n1 = {n1}", f"c1 = {c1}",
                          f"n2 = {n2}", f"c2 = {c2}", f"e = {e}"],
        "academy{rsa_shared_prime}")

    # 10 boneh_durfee: d ~ n^0.30 (beyond Wiener)
    p, q = rand_prime(384), rand_prime(384)
    n = p*q; phi = (p-1)*(q-1)
    d = random.getrandbits(230) | 1
    e = pow(d, -1, phi)
    m = flag_int("boneh_durfee"); c = pow(m, e, n)
    add("boneh_durfee", [f"n = {n}", f"e = {e}", f"c = {c}"],
        "academy{rsa_boneh_durfee}")

    # 11 partial_p: high bits of p known (Coppersmith class)
    p = rand_prime(512); q = rand_prime(512)
    n = p*q; e = 65537
    m = flag_int("partial_p"); c = pow(m, e, n)
    p_high = p >> 160  # top 352 bits of p
    add("partial_p", [f"n = {n}", f"e = {e}", f"c = {c}",
                       f"p_high = {p_high}  # high {512-160} bits of p"],
        "academy{rsa_partial_p}")

    return cases

def main():
    d = tempfile.mkdtemp(prefix="rsa_battery_")
    try:
        cases = build_cases(d)
        results = []
        for name, path, expected in cases:
            r = subprocess.run(
                [sys.executable, "autocrypt.py", path, "--timeout", "25",
                 "--json", "--top", "6"],
                capture_output=True, text=True, timeout=60)
            import json
            found = None
            try:
                out = json.loads(r.stdout)
                for res in out.get("results", []):
                    pt = res.get("plaintext", "")
                    if expected in pt:
                        found = res.get("chain", "")
                        break
                if found is None and out.get("results"):
                    found = "MISMATCH: " + out["results"][0].get("chain", "")
            except Exception as e:
                found = "ERR: " + str(e)
            status = "PASS" if found and not found.startswith(("MISMATCH", "ERR")) else "FAIL"
            results.append((status, name, found))
            print(f"{status:4} {name:18} {found}")
        print("\nsummary: %d/%d solved" % (sum(1 for s,_,_ in results if s=="PASS"), len(results)))
    finally:
        shutil.rmtree(d, ignore_errors=True)

if __name__ == "__main__":
    main()
