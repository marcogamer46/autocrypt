"""Fuzz smoke test: random/malformed inputs must never crash or overrun."""
import random
import re
import time

import solvers  # noqa: F401  (registers everything)
from core import Context, search
from scoring import assess

rng = random.Random(0xC0FFEE)
CASES = []


def add(name, data):
    CASES.append((name, data))


add("empty", b"")
add("random-1k", bytes(rng.randrange(256) for _ in range(1024)))
add("ascii-random", bytes(rng.randrange(32, 127) for _ in range(512)))
add("5000xA", b"A" * 5000)
add("unicode", "щщщ 🎉 academy{utf8} äöü".encode("utf-8"))
add("numbers-only", " ".join(str(rng.randrange(10**9)) for _ in range(40)).encode())
add("malformed-rsa", b"n=abc e=xyz c=12")
add("malformed-dh", b"g=2 p=0 A=1 B=1 enc=zz")
add("malformed-dsa", b"q=1 r=2 s1=3 s2=4 h1=5 h2=6")
add("malformed-fr", b"c1 c2 diff N")
add("nested-b64-junk", b"aGVsbG8gd29ybGQ=" * 50)
add("half-hex", b"48656c6c6f21")

failures = []
for name, data in CASES:
    t0 = time.monotonic()
    ctx = Context(deadline=t0 + 8,
                  flag_regex=re.compile(r"\w{1,40}\{.*?\}", re.DOTALL),
                  assess=assess)
    try:
        search(data, ctx, top=5)
    except Exception as exc:  # noqa: BLE001
        failures.append((name, f"raised {type(exc).__name__}: {exc}"))
        continue
    elapsed = time.monotonic() - t0
    if elapsed > 10:
        failures.append((name, f"overran {elapsed:.1f}s"))

print(f"fuzz cases: {len(CASES)}")
if failures:
    for name, why in failures:
        print(f"  FAIL {name}: {why}")
    raise SystemExit(1)
print("ALL FUZZ CASES OK")
