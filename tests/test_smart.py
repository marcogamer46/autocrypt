"""Phase 6 smart-mode tests: node-budget determinism, structural family gate,
learning reproducibility, and the benchmark generator smoke test."""
import base64
import json
import os
import sys as _sys
from pathlib import Path as _Path

# The repo's run_all_tests.sh executes each test_*.py as a standalone script
# (so sys.path[0] is tests/), while pytest adds the repo root. Add the root so
# gen_chains.py (a repo-root tool) imports in both modes.
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import pytest

from autocrypt.core import fingerprint, _applicable
from autocrypt.cli import solve_data
from autocrypt.learning import load_snapshot, learned_prior_map, snapshot_digest
from gen_chains import gen_split, _caesar, OPS
import random


# ---------------------------------------------------------------- family gate ---

def test_family_hash_prunes_classical_not_decoders():
    # md5 hex digest: family == "hash"
    fp = fingerprint(b"5d41402abc4b2a76b9719d911017c592")
    assert fp["hashes"] == ["MD5 or NTLM"]
    assert fp["family"] == "hash"
    # classical letter-ciphers pruned, decoders and hash-crack kept
    for name in ("caesar", "ROT13", "atbash", "affine", "vigenere-family",
                 "rail-fence", "columnar-transposition", "playfair",
                 "monoalphabetic-substitution"):
        assert not _applicable(name, fp, ()), name
    assert _applicable("hex", fp, ())
    assert _applicable("base64", fp, ())
    assert _applicable("hash-crack", fp, ())


def test_family_ic_prunes_substitution_only_large_alpha_pure():
    # Synthetic monoalphabetic-looking sample with low IC and >=100 letters.
    s = (b"qwertyuiopasdfghjklzxcvbnm" * 6)  # 156 letters, very low IC
    fp = fingerprint(s)
    assert fp["alpha_pure"]
    assert fp["nletters"] >= 100
    assert fp["ic"] < 0.045
    assert not _applicable("monoalphabetic-substitution", fp, ())
    # but a short/low-letter ambiguous sample is never pruned
    fp2 = fingerprint(b"ahx")
    assert _applicable("monoalphabetic-substitution", fp2, ())


def test_family_encoding_text():
    fp = fingerprint(base64.b64encode(b"hello world"))
    assert fp["family"] == "encoding"
    assert _applicable("caesar", fp, ())  # encodings never prune decoders


# ------------------------------------------------------------- determinism -----

def test_smart_node_budget_deterministic():
    ct = _caesar("the quick brown fox jumps over the lazy dog", 7).encode()
    r1 = solve_data(ct, top=6, jobs=1, timeout=12.0, node_budget=80,
                    failure_log_path=None)
    r2 = solve_data(ct, top=6, jobs=1, timeout=12.0, node_budget=80,
                    failure_log_path=None)
    c1 = [(x["chain"], x["plaintext"], x["confidence"]) for x in r1[1]]
    c2 = [(x["chain"], x["plaintext"], x["confidence"]) for x in r2[1]]
    assert c1 == c2
    # both runs must actually recover the shift-7 plaintext
    assert any("quick brown fox" in p for _, p, _ in c1)


def test_smart_determinism_matches_budget_loop():
    # The node budget must actually bind the traversal: a budget below the
    # natural (unbudgeted) node count must cap expansion below it.
    ct = _caesar("hello world this is a test of the budget loop", 3).encode()
    _fp, _res_nat, ctx_nat = solve_data(ct, top=4, jobs=1, timeout=12.0,
                                         failure_log_path=None)
    natural = ctx_nat.stats["nodes_expanded"]
    assert natural >= 2  # the smoke has a real traversal
    _fp, _res_a, ctx_a = solve_data(ct, top=4, jobs=1, timeout=12.0,
                                     node_budget=3, failure_log_path=None)
    assert ctx_a.stats["nodes_expanded"] <= 3
    assert ctx_a.stats["nodes_expanded"] < natural  # budget bound it


def test_default_path_unchanged_no_budget():
    ct = _caesar("the quick brown fox jumps over the lazy dog", 7).encode()
    _fp, res, _ctx = solve_data(ct, top=4, jobs=1, timeout=20.0,
                                 failure_log_path=None)
    assert any("quick brown fox" in str(x.get("plaintext")) for x in res)


# ---------------------------------------------------------------- learning -----

def test_learning_snapshot_frozen():
    import tempfile, os
    lines = [
        {"chain": "Base64 -> hex", "confidence": 0.95},
        {"chain": "vigenere-family(key=LEMON)", "confidence": 0.9},
        {"chain": "caesar(shift=7)", "confidence": 0.4},  # below floor
        {"chain": "hex", "confidence": 0.75},
    ]
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "solved.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(json.dumps(ln) + "\n")
        recs = load_snapshot(p)
        assert snapshot_digest(recs) == snapshot_digest(load_snapshot(p))
        m1 = learned_prior_map(recs, "encoding")
        m2 = learned_prior_map(load_snapshot(p), "encoding")
        assert m1 == m2  # reproducible
        assert "base64" in m1 or "hex" in m1
        # low-confidence chain never contributes
        assert "caesar" not in m1
        # different snapshot content -> different priors (family-sensitive)
        recs2 = (( "base64", 1, 0.95), ("hex", 0, 0.75))
        m3 = learned_prior_map(recs2, "encoding")
        assert m3 != m1 or m3 == {}


def test_learning_missing_file_empty():
    assert load_snapshot("definitely_missing_never_exists.jsonl") == ()
    assert learned_prior_map((), "unknown") == {}


# ---------------------------------------------------------------- benchmark -----

def test_gen_chains_smoke():
    rng = random.Random(1234)
    records = gen_split(rng, 10)
    assert len(records) == 10
    for r in records:
        assert 1 <= r["depth"] <= 6
        assert r["steps"]
        assert r["plaintext_type"] in ("english", "flag")
        ct = base64.b64decode(r["ciphertext_b64"]).decode("utf-8")
        assert isinstance(ct, str) and len(ct) > 0
        # the chain must actually transform: applying ops reproduces ciphertext
        cur = r["plaintext"]
        for st in r["steps"]:
            op = next(o for o in OPS if o[0] == st["op"])
            cur = op[2](cur, st["params"])
        assert cur == ct


if __name__ == "__main__":
    # Standalone runner (the repo's run_all_tests.sh executes each test_*.py
    # as a script, not under pytest).
    import sys as _sys
    _fns = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    _bad = 0
    for _fn in _fns:
        try:
            _fn()
            print("PASS", _fn.__name__)
        except Exception as _e:
            _bad += 1
            print("FAIL", _fn.__name__, repr(_e))
    _sys.exit(1 if _bad else 0)
