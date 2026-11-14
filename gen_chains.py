#!/usr/bin/env python3
"""Phase 6 benchmark generator: chained-transform CTF cipher problems.

Generates two disjoint, fixed-seed splits:
  - TRAIN (solved_chains_train.jsonl)  — used during development/tuning.
  - HOLDOUT (solved_chains_holdout.jsonl) — run ONLY at the very end. Its
    seed is deliberately kept out of the agent's working context so the
    system cannot overfit to it. Individual holdout failures are never
    printed — only aggregate solve rates by depth / step / plaintext-type.

Usage:
  python gen_chains.py gen                        # write both splits (500 each)
  python gen_chains.py gen --n 200                # smaller (smoke) splits
  python gen_chains.py report --split train       # solve TRAIN, aggregate
  python gen_chains.py report --split holdout     # solve HOLDOUT, aggregate
  python gen_chains.py report --n 50 --split train

"Revert overfitting" rule: if TRAIN solve rate >> HOLDOUT solve rate, the
learning/params are overfit and must be reverted. The report prints both sides'
rates side by side.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import sys
from pathlib import Path

TRAIN_FILE = "solved_chains_train.jsonl"
HOLDOUT_FILE = "solved_chains_holdout.jsonl"
SEED_TRAIN = 20260101
SEED_HOLDOUT = 20261115  # keep out of the agent's tuning context until the end
MAX_DEPTH = 6

_ENGLISH_SENTENCES = [
    "the quick brown fox jumps over the lazy dog",
    "pack my box with five dozen liquor jugs",
    "how vexingly quick daft zebras jump",
    "sphinx of black quartz judge my vow",
    "the five boxing wizards jump quickly",
    "two driven jocks help fax my big quiz",
    "we promptly judged antique ivory buckles for the next prize",
    "crazy fredrick bought many very exquisite opal jewels",
]
_FLAG_PREFIXES = ["flag", "ctf", "picoCTF", "htb", "academy", "dice", "uiuctf"]


def _flag(rng: random.Random) -> str:
    pre = rng.choice(_FLAG_PREFIXES)
    body = "_".join(rng.choice(_ENGLISH_SENTENCES).split()[: rng.randint(2, 5)])
    body = body.replace(" ", "_")
    return f"{pre}{{{body}}}"


# --- transform library: each op is (name, forward(plaintext, params) -> ct) ---
# The solver direction is the inverse; here we inverse the chain so the
# benchmark exercises exactly the code path users run.

def _caesar(s, k):
    out = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr(65 + (ord(ch) - 65 + k) % 26))
        elif "a" <= ch <= "z":
            out.append(chr(97 + (ord(ch) - 97 + k) % 26))
        else:
            out.append(ch)
    return "".join(out)


def _affine(s, a, b):
    out = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr(65 + ((ord(ch) - 65) * a + b) % 26))
        elif "a" <= ch <= "z":
            out.append(chr(97 + ((ord(ch) - 97) * a + b) % 26))
        else:
            out.append(ch)
    return "".join(out)


def _vigenere(s, key):
    out, j = [], 0
    for ch in s:
        if ch.isalpha():
            k = ord(key[j % len(key)]) - ord("A")
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr(base + (ord(ch) - base + k) % 26))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def _rail(s, rails):
    if rails < 2:
        return s
    rows = [[] for _ in range(rails)]
    r, down = 0, 1
    for ch in s:
        rows[r].append(ch)
        if r == 0:
            down = 1
        elif r == rails - 1:
            down = -1
        r += down
    return "".join("".join(row) for row in rows)


def _scytale(s, rows):
    if rows < 2:
        return s
    cols = (len(s) + rows - 1) // rows
    s = s + " " * (cols * rows - len(s))
    return "".join(s[r * cols + c] for c in range(cols) for r in range(rows)).rstrip(" ")


def _morse(s):
    table = {"a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".",
             "f": "..-.", "g": "--.", "h": "....", "i": "..", "j": ".---",
             "k": "-.-", "l": ".-..", "m": "--", "n": "-.", "o": "---",
             "p": ".--.", "q": "--.-", "r": ".-.", "s": "...", "t": "-",
             "u": "..-", "v": "...-", "w": ".--", "x": "-..-", "y": "-.--",
             "z": "--..", "0": "-----", "1": ".----", "2": "..---",
             "3": "...--", "4": "....-", "5": ".....", "6": "-....",
             "7": "--...", "8": "---..", "9": "----."}
    return " ".join(table.get(ch.lower(), ch) for ch in s)


OPS = [
    ("caesar", lambda rng: {"k": rng.randint(1, 25)},
     lambda s, p: _caesar(s, p["k"])),
    ("rot13", lambda rng: {}, lambda s, p: _caesar(s, 13)),
    ("atbash", lambda rng: {},
     lambda s, p: s.translate(str.maketrans(
         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
         "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"))),
    ("affine", lambda rng: {"a": rng.choice([1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]),
                            "b": rng.randint(0, 25)},
     lambda s, p: _affine(s, p["a"], p["b"])),
    ("vigenere", lambda rng: {"key": rng.choice(["KEY", "LEMON", "SECRET", "CIPHER", "XOR"])},
     lambda s, p: _vigenere(s, p["key"])),
    ("rail-fence", lambda rng: {"rails": rng.randint(2, 6)},
     lambda s, p: _rail(s, p["rails"])),
    ("scytale", lambda rng: {"rows": rng.randint(2, 6)},
     lambda s, p: _scytale(s, p["rows"])),
    ("hex", lambda rng: {}, lambda s, p: s.encode("utf-8").hex()),
    ("base64", lambda rng: {}, lambda s, p: base64.b64encode(s.encode("utf-8")).decode("ascii")),
    ("base32", lambda rng: {}, lambda s, p: base64.b32encode(s.encode("utf-8")).decode("ascii")),
    ("binary", lambda rng: {},
     lambda s, p: " ".join(f"{b:08b}" for b in s.encode("utf-8"))),
    ("morse", lambda rng: {}, lambda s, p: _morse(s)),
]


def generate_chain(rng: random.Random, depth: int):
    """Pick `depth` distinct ops (no adjacent duplicate family) and apply them
    in sequence to a plaintext. Returns (plaintext, type, steps, ciphertext)."""
    plain_type = rng.choice(["english", "flag"])
    plain = rng.choice(_ENGLISH_SENTENCES) if plain_type == "english" else _flag(rng)
    steps = []
    cur = plain
    used = []
    for _ in range(depth):
        # pick an op not equal to the last one (avoid trivial no-op stacking)
        while True:
            op = rng.choice(OPS)
            if not used or op[0] != used[-1]:
                break
        used.append(op[0])
        params = op[1](rng)
        cur = op[2](cur, params)
        steps.append({"op": op[0], "params": params})
    return plain, plain_type, steps, cur


def gen_split(rng, n):
    records = []
    for i in range(n):
        depth = rng.randint(1, MAX_DEPTH)
        plain, plain_type, steps, ct = generate_chain(rng, depth)
        records.append({
            "id": i, "depth": depth, "steps": steps,
            "plaintext_type": plain_type, "plaintext": plain,
            "ciphertext_b64": base64.b64encode(ct.encode("utf-8")).decode("ascii"),
        })
    return records


def write_split(path, records, seed):
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"seed": seed, "count": len(records), "max_depth": MAX_DEPTH}) + "\n")
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(records)} records -> {path}")


# ---------------------------------------------------------------- reporting ---

def _normalize(s):
    import re as _re
    return _re.sub(r"[^A-Za-z0-9]", "", s).lower()


def solve_one(ct: bytes, top=8, jobs=2):
    from autocrypt.cli import solve_data
    try:
        _fp, res, _ctx = solve_data(ct, top=top, jobs=jobs, timeout=25.0,
                                     max_depth=8, failure_log_path=None)
        texts = [str(r.get("plaintext") or "") for r in res]
        flags = [str(r.get("plaintext") or "") for r in res if r.get("is_flag")]
        return texts, flags
    except Exception:
        return [], []


def report(path, n, verbose=False):
    recs = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            line = line.strip()
            if not line:
                continue
            recs.append(json.loads(line))
    if n is not None and n < len(recs):
        recs = recs[:n]
    by_depth = {}
    by_step = {}
    by_type = {}
    total = solved = 0
    for r in recs:
        ct = base64.b64decode(r["ciphertext_b64"])
        target = _normalize(r["plaintext"])
        texts, flags = solve_one(ct)
        hit = target in {_normalize(t) for t in texts} or target in {_normalize(f) for f in flags}
        total += 1
        solved += int(hit)
        d = r["depth"]
        by_depth.setdefault(d, [0, 0])
        by_depth[d][1] += 1
        by_depth[d][0] += int(hit)
        first = r["steps"][0]["op"]
        by_step.setdefault(first, [0, 0])
        by_step[first][1] += 1
        by_step[first][0] += int(hit)
        t = r["plaintext_type"]
        by_type.setdefault(t, [0, 0])
        by_type[t][1] += 1
        by_type[t][0] += int(hit)
        if verbose and not hit:
            pass  # never print individual failures
    print(f"\n=== Report: {Path(path).name} ({total} records, {solved} solved, "
          f"{100.0 * solved / max(1, total):.1f}%) ===")
    print(f"\nsolve rate by depth:")
    for d in sorted(by_depth):
        ok, n = by_depth[d]
        print(f"  depth {d}: {ok}/{n} = {100.0 * ok / max(1, n):.1f}%")
    print(f"\nsolve rate by first step:")
    for s in sorted(by_step):
        ok, n = by_step[s]
        print(f"  {s}: {ok}/{n} = {100.0 * ok / max(1, n):.1f}%")
    print(f"\nsolve rate by plaintext-type:")
    for t in sorted(by_type):
        ok, n = by_type[t]
        print(f"  {t}: {ok}/{n} = {100.0 * ok / max(1, n):.1f}%")
    return total, solved


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["gen", "report"])
    ap.add_argument("--n", type=int, default=500, help="records per split (gen) or cap (report)")
    ap.add_argument("--split", choices=["train", "holdout"], default="train")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--seed-train", type=int, default=SEED_TRAIN)
    ap.add_argument("--seed-holdout", type=int, default=SEED_HOLDOUT)
    args = ap.parse_args()
    if args.mode == "gen":
        train = gen_split(random.Random(args.seed_train), args.n)
        write_split(TRAIN_FILE, train, args.seed_train)
        hold = gen_split(random.Random(args.seed_holdout), args.n)
        write_split(HOLDOUT_FILE, hold, args.seed_holdout)
    else:
        path = TRAIN_FILE if args.split == "train" else HOLDOUT_FILE
        report(path, args.n, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
