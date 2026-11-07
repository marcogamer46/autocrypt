"""Root-finding for integer polynomials via Cantor-Zassenhaus mod a big prime.

Finds all integer roots r in [0, bound) of an integer polynomial with huge
coefficients (from LLL-reduced Coppersmith vectors). Works by picking a prime
P > bound, finding all roots of the polynomial modulo P using Cantor-Zassenhaus
linear-factor splitting, then verifying each candidate exactly over Z.

The degree is small (<= ~12) so naive polynomial arithmetic is plenty fast.
"""
import math, random

def poly_mod(p, m):
    return [x % m for x in p]

def poly_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p

def poly_add(p, q, m):
    n = max(len(p), len(q))
    r = [0]*n
    for i in range(len(p)):
        r[i] = (r[i] + p[i]) % m
    for i in range(len(q)):
        r[i] = (r[i] + q[i]) % m
    return poly_trim(r)

def poly_sub(p, q, m):
    n = max(len(p), len(q))
    r = [0]*n
    for i in range(len(p)):
        r[i] = (r[i] + p[i]) % m
    for i in range(len(q)):
        r[i] = (r[i] - q[i]) % m
    return poly_trim(r)

def poly_mul(p, q, m):
    r = [0]*(len(p)+len(q)-1)
    for i, a in enumerate(p):
        if a:
            for j, b in enumerate(q):
                r[i+j] = (r[i+j] + a*b) % m
    return poly_trim(r)

def poly_scalar_mul(p, s, m):
    return [x*s % m for x in p]

def poly_powmod(p, e, f, m):
    result = [1]
    base = poly_mod(p, m)
    while e > 0:
        if e & 1:
            result = poly_mod(poly_mul(result, base, m), m)
            result = poly_mod(poly_rem(result, f, m), m)
        e >>= 1
        if e:
            base = poly_mod(poly_mul(base, base, m), m)
            base = poly_mod(poly_rem(base, f, m), m)
    return poly_mod(result, m)

def poly_rem(a, b, m):
    a = poly_mod(list(a), m)
    b = poly_trim(list(b))
    if len(b) == 1 and b[0] == 0:
        return [0]
    db = len(b) - 1
    inv_lc = pow(b[-1], -1, m)
    while len(a) - 1 >= db:
        if len(a) == 1 and a[0] == 0:
            break
        shift = len(a) - 1 - db
        coef = a[-1] * inv_lc % m
        for i in range(db + 1):
            a[shift + i] = (a[shift + i] - coef * b[i]) % m
        while len(a) > 1 and a[-1] == 0:
            a.pop()
    return poly_trim(a)

def poly_gcd(a, b, m):
    a = poly_trim(list(a)); b = poly_trim(list(b))
    while len(b) > 1 or (len(b) == 1 and b[0] != 0):
        a, b = b, poly_rem(a, b, m)
    # b is now zero polynomial
    # normalize a
    lc = a[-1]
    inv = pow(lc, -1, m)
    return [x * inv % m for x in a]

def poly_deriv(p, m):
    d = len(p) - 1
    if d < 1:
        return [0]
    return poly_trim([ (i * p[i]) % m for i in range(1, len(p)) ])

def poly_divmod(a, b, m):
    """return (q, r) such that a = q*b + r mod m, b monic-ish"""
    a = poly_mod(list(a), m); b = poly_trim(list(b))
    db = len(b) - 1
    inv_lc = pow(b[-1], -1, m)
    q = [0]*max(0, len(a)-db)
    a = list(a)
    while len(a) - 1 >= db:
        shift = len(a) - 1 - db
        coef = a[-1] * inv_lc % m
        q[shift] = coef
        for i in range(db + 1):
            a[shift + i] = (a[shift + i] - coef * b[i]) % m
        while len(a) > 1 and a[-1] == 0:
            a.pop()
    return poly_trim(q), poly_trim(a)

def _roots_mod_prime(poly, P):
    """All roots of poly in F_P (returns list of residues)."""
    f = poly_trim(list(poly))
    # make monic
    inv = pow(f[-1], -1, P)
    f = [(c*inv) % P for c in f]
    # squarefree: f = f / gcd(f, f')
    fp = poly_deriv(f, P)
    g = poly_gcd(f, fp, P)
    if deg_ok(g) <= 0:
        sqfree = f
    else:
        sqfree = poly_rem(f, g, P)
    factors = split_linear(sqfree, P)
    roots = []
    for fac in factors:
        if len(fac) == 2:
            r = (-fac[0] * pow(fac[1], -1, P)) % P
            roots.append(r)
    return roots

def deg_ok(p):
    return len(p) - 1

def split_linear(f, P):
    """Return list of irreducible factors (linear ones) of squarefree f over F_P."""
    # f is squarefree, factors are distinct
    factors = []
    queue = [f]
    while queue:
        cur = queue.pop()
        if len(cur) <= 1:          # zero / constant, skip
            continue
        if len(cur) == 2:          # linear factor
            factors.append(cur)
            continue
        # try to split cur
        split = False
        for _ in range(200):
            a = random.randrange(P)
            # g = (x + a)^((P-1)/2) - 1 mod cur
            base = [a, 1]  # x + a
            e = (P - 1) // 2
            h = poly_powmod(base, e, cur, P)
            h = poly_sub(h, [1], P)
            gg = poly_gcd(cur, h, P)
            if deg_ok(gg) > 0 and deg_ok(gg) < deg_ok(cur):
                q, r = poly_divmod(cur, gg, P)
                factors.append(gg)
                factors.append(q)
                queue.append(gg)
                queue.append(q)
                split = True
                break
        if not split:
            # couldn't split into linear? add as-is
            factors.append(cur)
    return factors

def find_roots(coeffs, bound):
    """Find all integer roots r with 0 <= r < bound of integer poly coeffs
    (monomial order, ascending degree)."""
    # strip trailing zeros
    d = len(coeffs) - 1
    while d > 0 and coeffs[d] == 0:
        d -= 1
    if d < 1:
        return []
    if bound <= 1:
        return [0] if coeffs[0] == 0 else []
    # pick prime P > bound
    P = next_prime(bound)
    roots_mod = _roots_mod_prime(coeffs[:d+1], P)
    out = []
    for r in roots_mod:
        r = r % P
        if r < bound:
            if eval_poly(coeffs[:d+1], r) == 0:
                out.append(r)
    return sorted(set(out))

def eval_poly(coeffs, x):
    v = 0
    for c in reversed(coeffs):
        v = v * x + c
    return v

def is_prime(nn):
    if nn < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29,31,37]:
        if nn % p == 0:
            return nn == p
    d, s = nn-1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in [2,3,5,7,11,13,17,19,23,29,31,37]:
        if a >= nn:
            continue
        x = pow(a, d, nn)
        if x in (1, nn-1):
            continue
        for _ in range(s-1):
            x = x*x % nn
            if x == nn-1:
                break
        else:
            return False
    return True

def next_prime(nn):
    n = nn + 1
    while not is_prime(n):
        n += 1
    return n
