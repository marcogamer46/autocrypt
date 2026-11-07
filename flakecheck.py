#!/usr/bin/env python3
"""Flake evidence: run a hex-family grid REP times idle and (optionally) with
CPU-contending autocrypt copies, and report every case whose TOP result
(chain + plaintext) differs between runs."""
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_hexfamily as H

CONTEND_FIXTURES = [
    "fixtures/real_dlp/output.txt",
    "fixtures/dlp1024.txt",
    "fixtures/hash_sample.txt",
    "fixtures/dlp_neg_safe.txt",
]


def contention_helpers(n=4):
    procs = []
    for i in range(n):
        fx = CONTEND_FIXTURES[i % len(CONTEND_FIXTURES)]
        if not Path(fx).exists():
            continue
        procs.append(subprocess.Popen(
            [sys.executable, "autocrypt.py", fx, "--timeout", "30"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return procs


def main():
    seed = int(sys.argv[1])
    grid = sys.argv[sys.argv.index("--grid") + 1] if "--grid" in sys.argv else "d34"
    reps = int(sys.argv[sys.argv.index("--reps") + 1]) if "--reps" in sys.argv else 3
    contend = "--contend" in sys.argv
    g = H.Gen(seed)
    if "--xorfam" in sys.argv:
        import test_xorfamily as XF
        cases = XF.Gen(seed).build()
    else:
        griddef = {"d12": H.D12, "d34": H.D34}[grid]
        cases = g.build(10, cipher=[c for c, _ in griddef],
                        layers=[l for _, l in griddef])
    sigs = {i: [] for i in range(10)}
    for rep in range(reps):
        helpers = contention_helpers() if contend else []
        time.sleep(2 if helpers else 0)
        for i, (name, data, flag) in enumerate(cases):
            out = H.run_case(data)
            if out:
                sigs[i].append((out[0]["chain"], out[0]["plaintext"]))
            else:
                sigs[i].append(None)
        for p in helpers:
            p.terminate()
    print(f"FLAKE seed={seed} grid={grid} reps={reps} contend={contend}")
    for i in range(10):
        uniq = set(sigs[i])
        if len(uniq) > 1:
            print(f"  DIFF case={i} ({cases[i][0]}) sigs={len(uniq)}")
            for s in uniq:
                print(f"      {s}")
        else:
            print(f"  stable case={i} ({cases[i][0]}) top={sigs[i][0]}")


if __name__ == "__main__":
    main()
