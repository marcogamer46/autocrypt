"""Regression: ROT13 on an "academy{...}" bundle with padding prefix.

The rot13.txt challenge decrypts via ROT13 to a string whose trailing wrapper is
"academy" (the prefix is padding). autocrypt must surface the canonical academy
flag at rank 0 with the "cracked ROT13" method.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")


def run_autocrypt(text):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        env = dict(os.environ, PYTHONPATH=ROOT)
        res = subprocess.run([PY, "-m", "autocrypt.cli", "--json", "--top", "10", path],
                             capture_output=True, text=True, env=env, cwd=ROOT,
                             timeout=180)
        m = re.search(r"\{.*\}", res.stdout, re.S)
        assert m, f"no JSON: {res.stdout[:1000]}"
        return __import__("json").loads(m.group(0))
    finally:
        os.unlink(path)


def main():
    cipher = "cultirisnpnqrzl{P7e1S_54I35_71Z3}"
    out = run_autocrypt(cipher)
    results = out.get("results", [])
    assert results, f"no results: {out}"
    top = results[0]
    flag = "academy{C7r1F_54V35_71M3}"
    assert top["plaintext"] == flag, f"rank0={top['plaintext']!r} want {flag!r}"
    assert "rot13" in top["chain"].lower(), top["chain"]
    assert top["confidence"] >= 0.95, top["confidence"]
    print("PASS: rot13 academy flag recovered at rank 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
