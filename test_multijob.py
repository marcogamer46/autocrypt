#!/usr/bin/env python3
"""G1 determinism: every fixture must produce identical top-3 (chain+plaintext)
with -j 1 and -j 4."""
import subprocess, sys, json, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
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

def run(path, jobs, extra=()):
    args = [sys.executable, "autocrypt.py", str(path), "--timeout", "35",
            "--json", "--top", "3", "--jobs", str(jobs)] + list(extra)
    r = subprocess.run(args, capture_output=True, text=True, timeout=70)
    try:
        out = json.loads(r.stdout or "[]")
        if isinstance(out, dict):
            out = out.get("results", [])
    except Exception:
        return None
    return [(x["chain"], x["plaintext"]) for x in out[:3]]

fails = []
for f in FIXTURES:
    p = TMP / f
    if not p.exists():
        continue
    a = run(p, 1)
    b = run(p, 4)
    if a is None or b is None or a != b:
        fails.append((f, a, b))
        print("FAIL", f)
    else:
        print("OK  ", f)
print(f"\nMULTIJOB: {len(FIXTURES)-len(fails)}/{len(FIXTURES)} equal")
sys.exit(1 if fails else 0)
