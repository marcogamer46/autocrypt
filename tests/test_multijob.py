#!/usr/bin/env python3
"""G1 determinism: every fixture must produce identical top-3 (chain+plaintext)
with -j 1 and -j 4.

Rewritten (BKLG-12) to be faster and more diagnostic:
  * runs the two jobs (and all fixtures) in parallel via a thread pool,
  * separates a run/JSON error from a genuine mismatch, and
  * prints the two result lists when a mismatch is found.
"""
import subprocess
import sys
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = ROOT / "fixtures"

FIXTURES = [
    "message.txt", "rsa_even.txt", "lfsr_sample.bin", "atbash_flag_shaped.txt",
    "t.txt", "c1_plain.txt", "c1_b64.txt", "z85_sample.txt", "custombase_sample.txt",
    "crt_sample.txt", "pp1_rsa.txt", "ec_sample.txt", "ecdsa_reuse.txt",
    "dsa_sample.txt", "sharedprime_sample.txt", "dpdq_sample.txt", "pqsum_sample.txt",
    "even_e_sample.txt", "fr_labeled.txt", "fr_unlabeled.txt", "lcg_sample.txt",
    "mt_sample.txt", "dh_dlp_sample.txt", "rc4_sample.txt", "hash_sample.txt",
    "dna_sample.txt", "twosym_sample.txt", "braille_sample.txt", "b32hex_sample.txt",
    "lsb_plane1.png", "wav_sample.wav", "enigma_direct.txt", "dlp512.txt",
    "dlp1024.txt", "dlp_dec_g2.txt", "real_dlp/output.txt", "real_seq/sequences.py",
    "sequences_synth.py",
]

TIMEOUT_S = 30
SUBPROC_TIMEOUT = TIMEOUT_S + 20
MAX_WORKERS = 4


def run(path, jobs):
    """Return (error, rows). rows = list of (chain, plaintext) for top 3.
    error is None on success, else a short diagnostic string."""
    args = [sys.executable, "-m", "autocrypt.cli", str(path), "--timeout", str(TIMEOUT_S),
            "--json", "--top", "3", "--jobs", str(jobs)]
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                            timeout=SUBPROC_TIMEOUT, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception as exc:
        return f"JSON-ERR:{type(exc).__name__}", None
    if not isinstance(out, list):
        return "BAD-JSON-SHAPE", None
    try:
        return None, [(x["chain"], x["plaintext"]) for x in out[:3]]
    except (KeyError, TypeError) as exc:
        return f"SHAPE-ERR:{type(exc).__name__}", None


def check_one(path):
    if not path.exists():
        return path.name, None, None, "SKIP missing"
    a = run(path, 1)
    b = run(path, 4)
    if a[0] or b[0]:
        return path.name, a, b, "RUN-ERROR"
    if a[1] != b[1]:
        return path.name, a, b, "MISMATCH"
    return path.name, a, b, "OK"


def main():
    paths = [TMP / f for f in FIXTURES]
    fails = []
    ran = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for name, a, b, status in ex.map(check_one, paths):
            if status == "SKIP missing":
                continue
            ran += 1
            if status == "OK":
                print("OK  ", name)
            else:
                fails.append((name, a, b, status))
                print("FAIL", name, status)
                if status == "MISMATCH":
                    print("    j=1:", a[1])
                    print("    j=4:", b[1])
                elif status == "RUN-ERROR":
                    print("    j=1 run:", a[0])
                    print("    j=4 run:", b[0])
    print(f"\nMULTIJOB: {ran - len(fails)}/{ran} equal")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
