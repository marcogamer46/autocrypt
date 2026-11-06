#!/usr/bin/env python3
"""Regression for the auto-parsing known-plaintext repeating-key XOR solver.

Training source: xorly (redpwn / picoCTF-style) raw generator. The source
embeds a sample plaintext, its ciphertext (hex), and the flag ciphertext
(hex) all under the same repeating key. autocrypt must recover the key from
the sample and decrypt the flag — no hand-fed crib.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHALLENGE = ROOT / "real_challenges" / "online_train" / "xorly" / "xorly.py"
EXPECTED_FLAG = "flag{xor_is_the_new_aes}"


def pipeline():
    args = ["python3", "autocrypt.py", str(CHALLENGE), "--timeout", "30",
            "--json", "--top", "5"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if not r.stdout:
        return False, "no json output"
    import json
    try:
        out = json.loads(r.stdout)
    except Exception:
        return False, "bad json"
    results = out.get("results", [])
    if not results:
        return False, "empty results"
    top_chain = results[0].get("chain", "")
    top_txt = results[0].get("plaintext", "")
    if "sample-keystream" in top_chain and EXPECTED_FLAG.lower() in top_txt.lower():
        return True, f"rank0: {top_chain}"
    # fall back: any result carries the flag
    for res in results:
        if EXPECTED_FLAG.lower() in res.get("plaintext", "").lower():
            return True, f"flag found in {res.get('chain')}"
    return False, f"flag not recovered (top: {top_chain})"


def main():
    ok, note = pipeline()
    print(f"sample-keystream-xor: {'PASS' if ok else 'FAIL'} ({note})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
