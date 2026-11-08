#!/usr/bin/env python3
"""Test script to find flaws in autocrypt components up to 4 billion."""

import re
import sys
import time
import random
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from solvers_more import factor_all, _pm1, _pp1, _rho, _is_prime
from core import Context

# Deterministic runs: seed RNG so results are reproducible across machines.
random.seed(20261108)

_FLAG_RE = re.compile(r"\w{1,40}\{.*?\}")

def test_factor_all_correctness(limit=1000000, sample_size=500):
    """Test factor_all correctness on random numbers up to limit."""
    print(f"Testing factor_all correctness on {sample_size} random numbers up to {limit}...")
    flaws = []
    
    for i in range(sample_size):
        # Generate random number up to limit
        n = random.randint(2, limit)
        
        # Skip if n is too small for meaningful test
        if n < 15:
            continue
            
        start_time = time.monotonic()
        flag_regex = __import__('re').compile(r'\w{1,40}\{.*?\}')
        ctx = Context(deadline=time.monotonic() + 10.0, flag_regex=flag_regex)  # 10 second timeout
        result = factor_all(n, ctx)
        elapsed = time.monotonic() - start_time
        
        if result is None:
            # Check if n is actually prime
            if _is_prime(n):
                # For prime, we expect a factorization, not None
                flaws.append(f"factor_all returned None for prime n={n} (time={elapsed:.3f}s)")
            else:
                flaws.append(f"factor_all returned None for composite n={n} (time={elapsed:.3f}s)")
        else:
            # Verify that the product of factors equals original n
            product = 1
            for prime, exp in result.items():
                product *= prime ** exp
                # Also check that each factor is prime
                if not _is_prime(prime):
                    flaws.append(f"factor_all reported non-prime factor {prime} for n={n}")
            if product != n:
                flaws.append(f"factor_all product mismatch for n={n}: got {product}, expected {n}")
            
            # Also check that all factors are indeed factors of n
            for prime in result:
                if n % prime != 0:
                    flaws.append(f"factor_all factor {prime} does not divide n={n}")
                    
        if elapsed > 5.0:  # Flag if taking too long
            flaws.append(f"factor_all too slow for n={n}: {elapsed:.3f}s")
            
        if (i+1) % 100 == 0:
            print(f"  Processed {i+1}/{sample_size} numbers...")
    
    return flaws

def test_specific_numbers():
    """Test specific numbers known to be tricky for factorization algorithms."""
    print("Testing specific tricky numbers...")
    flaws = []
    
    # Test numbers that are products of two primes where p-1 is smooth (good for p-1)
    # and where p-1 has large prime factors (bad for p-1)
    
    # Generate some primes
    def is_prime_simple(n):
        if n < 2:
            return False
        for i in range(2, int(math.isqrt(n)) + 1):
            if n % i == 0:
                return False
        return True
    
    # Get a list of primes up to 10000 for constructing test numbers
    primes = []
    for i in range(2, 10000):
        if is_prime_simple(i):
            primes.append(i)
    
    # Test products of two primes
    for _ in range(100):
        p = random.choice(primes)
        q = random.choice(primes)
        n = p * q
        if n > 4_000_000_000:
            continue
            
        start_time = time.monotonic()
        flag_regex = __import__('re').compile(r'\w{1,40}\{.*?\}')
        ctx = Context(deadline=time.monotonic() + 10.0, flag_regex=flag_regex)
        result = factor_all(n, ctx)
        elapsed = time.monotonic() - start_time
        
        if result is None:
            flaws.append(f"factor_all failed on semiprime n={n}={p}*{q}")
        else:
            product = 1
            for prime, exp in result.items():
                product *= prime ** exp
            if product != n:
                flaws.append(f"factor_all product mismatch for semiprime n={n}: got {product}")
    
    # Test powers of primes
    for _ in range(50):
        p = random.choice(primes)
        e = random.randint(2, 5)
        n = p ** e
        if n > 4_000_000_000:
            continue
            
        start_time = time.monotonic()
        flag_regex = __import__('re').compile(r'\w{1,40}\{.*?\}')
        ctx = Context(deadline=time.monotonic() + 10.0, flag_regex=flag_regex)
        result = factor_all(n, ctx)
        elapsed = time.monotonic() - start_time
        
        if result is None:
            flaws.append(f"factor_all failed on prime power n={n}={p}^{e}")
        else:
            product = 1
            for prime, exp in result.items():
                product *= prime ** exp
            if product != n:
                flaws.append(f"factor_all product mismatch for prime power n={n}: got {product}")
            # Check that we got the right factorization
            if len(result) != 1 or p not in result or result[p] != e:
                flaws.append(f"factor_all incorrect factorization for n={n}: got {result}, expected {{{p}: {e}}}")
    
    return flaws

def test_pollard_pm1():
    """Test Pollard p-1 implementation."""
    print("Testing Pollard p-1...")
    flaws = []
    
    # Generate a prime p such that p-1 is smooth
    def is_smooth(n, B):
        """Check if n is B-smooth (all prime factors <= B)"""
        temp = n
        for p in range(2, int(math.isqrt(temp)) + 1):
            while temp % p == 0:
                if p > B:
                    return False
                temp //= p
        if temp > B:
            return False
        return True
    
    # Find a prime p where p-1 is 1000-smooth
    smooth_primes = []
    for p in range(1000, 10000):
        if _is_prime(p) and is_smooth(p-1, 1000):
            smooth_primes.append(p)
    
    if not smooth_primes:
        print("  Warning: Could not find smooth primes for p-1 test")
    else:
        for p in smooth_primes[:10]:
            # Construct n = p * q where q is another prime
            q = random.choice([r for r in range(1000, 10000) if _is_prime(r) and r != p])
            n = p * q
            if n > 4_000_000_000:
                continue
                
            ctx = Context(deadline=time.monotonic() + 10.0,
                           flag_regex=__import__('re').compile(r'\w{1,40}\{.*?\}'))
            start_time = time.monotonic()
            factor = _pm1(n, B=5000)  # Use a small bound
            elapsed = time.monotonic() - start_time
            
            if factor is None:
                # Maybe p-1 is not smooth enough for B=5000, try with higher bound
                factor2 = _pm1(n, B=20000)
                if factor2 is None:
                    flaws.append(f"Pollard p-1 failed to find factor of n={n} (p={p}, q={q}) even with B=20000")
            else:
                if factor != p and factor != q:
                    flaws.append(f"Pollard p-1 returned wrong factor {factor} for n={n} (expected {p} or {q})")
                elif n % factor != 0:
                    flaws.append(f"Pollard p-1 factor {factor} does not divide n={n}")
    
    return flaws

def test_pollard_pp1():
    """Test Williams p+1 implementation."""
    print("Testing Williams p+1...")
    flaws = []
    
    # Similar to p-1 but for p+1 smooth
    def is_smooth(n, B):
        temp = n
        for p in range(2, int(math.isqrt(temp)) + 1):
            while temp % p == 0:
                if p > B:
                    return False
                temp //= p
        if temp > B:
            return False
        return True
    
    # Find a prime p where p+1 is 1000-smooth
    smooth_primes = []
    for p in range(1000, 10000):
        if _is_prime(p) and is_smooth(p+1, 1000):
            smooth_primes.append(p)
    
    if not smooth_primes:
        print("  Warning: Could not find smooth primes for p+1 test")
    else:
        for p in smooth_primes[:10]:
            q = random.choice([r for r in range(1000, 10000) if _is_prime(r) and r != p])
            n = p * q
            if n > 4_000_000_000:
                continue
                
            ctx = Context(deadline=time.monotonic() + 10.0,
                           flag_regex=__import__('re').compile(r'\w{1,40}\{.*?\}'))
            start_time = time.monotonic()
            factor = _pp1(n, ctx)
            elapsed = time.monotonic() - start_time
            
            if factor is None:
                # Try to see if p+1 is actually smooth enough
                if is_smooth(p+1, 200000):  # Using the default B from _pp1_moment
                    flaws.append(f"Williams p+1 failed to find factor of n={n} (p={p}, q={q}) despite p+1 being smooth")
            else:
                if factor != p and factor != q:
                    flaws.append(f"Williams p+1 returned wrong factor {factor} for n={n} (expected {p} or {q})")
                elif n % factor != 0:
                    flaws.append(f"Williams p+1 factor {factor} does not divide n={n}")
    
    return flaws

def test_rho():
    """Test Pollard rho implementation."""
    print("Testing Pollard rho...")
    flaws = []
    
    # Test on composite numbers that are not easy for p-1 or p+1
    for _ in range(50):
        # Generate two random primes
        p = random.randint(1000, 50000)
        q = random.randint(1000, 50000)
        # Make them prime-ish by checking small divisors
        while not _is_prime(p):
            p += 1
        while not _is_prime(q) or q == p:
            q += 1
        n = p * q
        if n > 4_000_000_000:
            continue
            
        ctx = Context(deadline=time.monotonic() + 10.0,
                       flag_regex=__import__('re').compile(r'\w{1,40}\{.*?\}'))
        start_time = time.monotonic()
        factor = _rho(n, ctx, limit=100000)
        elapsed = time.monotonic() - start_time
        
        if factor is None:
            # Rho might fail sometimes, but let's see if we can find a factor with more iterations
            factor2 = _rho(n, ctx, limit=500000)
            if factor2 is None:
                flaws.append(f"Pollard rho failed to find factor of n={n} (p={p}, q={q}) even with higher limit")
        else:
            if factor != p and factor != q and factor != n//p and factor != n//q:
                # Actually, factor could be p or q or n//p or n//q? Wait n//p = q, n//q = p
                # So factor should be either p or q
                flaws.append(f"Pollard rho returned unexpected factor {factor} for n={n} (expected {p} or {q})")
            elif n % factor != 0:
                flaws.append(f"Pollard rho factor {factor} does not divide n={n}")
    
    return flaws

def main():
    print("Starting flaw detection tests for autocrypt components up to 4 billion...")
    all_flaws = []
    
    # Test 1: Correctness of factor_all on random numbers
    flaws1 = test_factor_all_correctness(limit=1000000, sample_size=500)
    all_flaws.extend(flaws1)
    print(f"  Found {len(flaws1)} flaws in correctness test")
    
    # Test 2: Specific tricky numbers
    flaws2 = test_specific_numbers()
    all_flaws.extend(flaws2)
    print(f"  Found {len(flaws2)} flaws in specific numbers test")
    
    # Test 3: Pollard p-1
    flaws3 = test_pollard_pm1()
    all_flaws.extend(flaws3)
    print(f"  Found {len(flaws3)} flaws in p-1 test")
    
    # Test 4: Williams p+1
    flaws4 = test_pollard_pp1()
    all_flaws.extend(flaws4)
    print(f"  Found {len(flaws4)} flaws in p+1 test")
    
    # Test 5: Pollard rho
    flaws5 = test_rho()
    all_flaws.extend(flaws5)
    print(f"  Found {len(flaws5)} flaws in rho test")
    
    # Write flaws to file
    if all_flaws:
        with open(ROOT / "flaws.md", "w") as f:
            f.write("# Flaws Found in autocrypt Components\n\n")
            f.write(f"Total flaws found: {len(all_flaws)}\n\n")
            for i, flaw in enumerate(all_flaws, 1):
                f.write(f"{i}. {flaw}\n")
        print(f"\nWritten {len(all_flaws)} flaws to {ROOT / 'flaws.md'}")
    else:
        print("\nNo flaws found!")
        # Still create the file indicating no flaws
        with open(ROOT / "flaws.md", "w") as f:
            f.write("# Flaws Found in autocrypt Components\n\n")
            f.write("No flaws found in the tests conducted.\n")
    
    return 0 if len(all_flaws) == 0 else 1

if __name__ == "__main__":
    sys.exit(main())