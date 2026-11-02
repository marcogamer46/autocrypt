#!/usr/bin/env python3
"""Diagnose hex-layer family cases: fixpoint, solver run, ranking."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import json

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 20270306
TARGETS = [int(a) for a in sys.argv[2:] if a.isdigit()]
sys.argv = ["diag.py", str(SEED), "--matrix"]
import test_hexfamily as H

from core import Context, search, fingerprint, _free_fixpoint


def main():
    seed = SEED
    g = H.Gen(seed)
    cases = g.build(10, cipher=[c for c, _ in H.MATRIX],
                    layers=[l for _, l in H.MATRIX])
    which = TARGETS
    targets = which if which else range(len(cases))
    for i in targets:
        name, data, flag = cases[i]
        print(f"\n=== [{i}] {name} -> {flag} ===")
        print(f"input({len(data)}B): {data[:70]!r}")
        fp = fingerprint(data)
        print(f"fp: charset={fp.get('charset')} len={fp.get('length')} "
              f"ic={fp.get('ic')} entro={fp.get('entropy')} classes={fp.get('classes')}")
        fix = _free_fixpoint(data)
        if fix:
            newdata, names = fix
            print(f"FIXPOINT fired: chain {names} -> {newdata[:60]!r}")
        else:
            print("FIXPOINT: did not fire")
        ctx = Context(deadline=time.monotonic() + 30, flag_regex=__import__("re").compile(r"\w{1,40}\{.*?\}", __import__("re").DOTALL),
                      flag_regex_explicit=False, known_plaintext="", wordlist=[],
                      rsa_params={}, assess=__import__("scoring").assess, jobs=1)
        t0 = time.monotonic()
        res = search(data, ctx, top=25, max_depth=7)
        wall = time.monotonic() - t0
        print(f"status={res.status} wall={wall:.2f}s failures={ctx.failures[:3]}")
        print("solver times:", {k: round(v, 2) for k, v in sorted(ctx.solver_times.items(), key=lambda kv: -kv[1])[:12]})
        low = flag.lower()
        for rank, r in enumerate(res):
            mark = "  <== TRUE" if low in r["plaintext"].lower() else ""
            if rank < 12 or mark:
                print(f"  [{rank}] conf={r['confidence']} trust={r.get('_trust')} "
                      f"engok={r.get('_english_ok')} isflag={r.get('is_flag')} "
                      f"chain={r['chain']} text={r['plaintext'][:45]!r}{mark}")


if __name__ == "__main__":
    main()
