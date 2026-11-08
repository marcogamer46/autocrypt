"""Regression for the dictionary-based word-list substitution solver.

Builds a synthetic monoalphabetic substitution over a random sample of English
words (one per line) plus an encrypted flag phrase, then runs the full
autocrypt pipeline and asserts the *decrypted* flag appears at rank 0. The
solver must recover the substitution generically (word-pattern AC-3) -- no
hardcoded mapping or plaintext.
"""
import os
import random
import string
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_case(n_words=9000, seed=17):
    al = list(string.ascii_lowercase)
    shuffled = al[:]
    random.Random(seed).shuffle(shuffled)
    mapping = dict(zip(al, shuffled))          # plain -> cipher

    def enc(s):
        return "".join(mapping.get(c, c) if c.islower()
                       else mapping.get(c.lower(), c).upper() if c.isalpha()
                       else c for c in s)

    # sample words from the bundled dictionary
    words = []
    with open(os.path.join(HERE, "english_words.txt"), encoding="utf-8",
              errors="ignore") as f:
        for line in f:
            w = line.strip().lower()
            if w and w.isalpha() and 4 <= len(w) <= 12:
                words.append(w)
            if len(words) >= n_words:
                break
    sample = random.Random(seed + 1).sample(words, min(n_words, len(words)))
    plain_flag = "perhaps_the_dog_jumped_over_was_just_tired"
    body = "\n".join(enc(w) for w in sample) + "\n" + enc(plain_flag) + "\n"
    import json
    meta = {"mapping": mapping, "plain_flag": plain_flag, "count": len(sample)}
    return body, meta


def test_substitution_wordlist():
    body, meta = build_case()
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
        r = subprocess.run(
            [sys.executable, "-m", "autocrypt.cli", path, "--timeout", "25", "--json"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=90)
        out = None
        if r.stdout.strip():
            import json
            try:
                out = json.loads(r.stdout)
            except Exception:
                out = None
        if not isinstance(out, dict):
            out = {"results": []}
        res = out.get("results", []) or []
        target = meta["plain_flag"]
        rank = next((i for i, x in enumerate(res)
                     if target.lower() in x["plaintext"].lower()), None)
        assert rank == 0, (
            f"flag not at rank 0 (rank={rank}); top="
            f"{res[0]['chain'] + ' -> ' + res[0]['plaintext'][:60] if res else 'NONE'}")
        assert "monoalphabetic" in res[0]["chain"] and "dictionary" in res[0]["chain"], \
            res[0]["chain"]
        # ensure the top hit is genuinely decrypted, not a false-positive flag
        assert res[0]["plaintext"].strip() == target, res[0]["plaintext"]
        print("OK  substitution-wordlist rank0 ->", target)
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_substitution_wordlist()
