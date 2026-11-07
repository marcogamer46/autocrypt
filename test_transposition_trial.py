"""Regression for the block-transposition solver (transposition-trial family).

The PicoCTF "transposition-trial" cipher scrambles a message by permuting the
characters of each 3-char block ([1,2,3] -> [3,1,2]). This test synthesizes a
flag-shaped bundle, encrypts it two way, and asserts autocrypt recovers the
flag at rank 0 with the "cracked block transposition" method.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")


def transposition_trial(s):
    # Encryption: each 3-char block is reordered [a,b,c] -> [b,c,a]
    # (i.e. the inverse of the decryption order [c,a,b] the solver applies).
    out = []
    for i in range(0, len(s), 3):
        blk = s[i:i + 3]
        if len(blk) == 3:
            out.append(blk[1] + blk[2] + blk[0])
        else:
            out.append(blk)
    return "".join(out)


def run_autocrypt(text):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        env = dict(os.environ, PYTHONPATH=ROOT)
        res = subprocess.run([PY, "autocrypt.py", "--json", "--top", "10", path],
                             capture_output=True, text=True, env=env, cwd=ROOT,
                             timeout=180)
        raw = res.stdout
        m = re.search(r"\{.*\}", raw, re.S)
        assert m, f"no JSON output: {raw[:1000]}"
        return __import__("json").loads(m.group(0))
    finally:
        os.unlink(path)


def main():
    plain = "The flag is academy{7R4N5P051N6_15_3XP3N51V3_C1CBA2A2}"
    cipher = transposition_trial(plain)
    assert cipher == "heTfl g as icaaemd{7y4NRP051N5_16_35P3X51N3_V1CCA2B2}A", cipher
    out = run_autocrypt(cipher)
    results = out.get("results", [])
    assert results, f"no results: {out}"
    top = results[0]
    flag = "academy{7R4N5P051N6_15_3XP3N51V3_C1CBA2A2}"
    assert top["plaintext"] == flag, f"rank0={top['plaintext']!r} want {flag!r}"
    assert "block transposition" in top["chain"].lower(), top["chain"]
    assert top["confidence"] >= 0.95, top["confidence"]
    print("PASS: transposition-trial recovered at rank 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
