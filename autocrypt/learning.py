"""Phase 6 learning: deterministic solver-chain priors from a frozen snapshot.

Design contract (per the design review):
- Learning is a PURE function of a deterministic, read-only history snapshot.
- It NEVER writes ``solved_chains.jsonl`` during a run that reads it.
- Priors are derived from a fixed seed applied to (input family, snapshot
  digest); the snapshot is frozen at run start and its ordering/format is
  pinned (we sort before hashing).
- Thus a fresh checkout, a different machine, or a mutated history file all
  produce the SAME priors for the same (family, snapshot), and a run that
  reads a snapshot is reproducible.
"""
from __future__ import annotations

import hashlib
import json

SNAPSHOT_PATH_DEFAULT = "solved_chains.jsonl"
_SOLVE_CONFIDENCE_FLOOR = 0.62


def load_snapshot(path: str) -> tuple:
    """Load and freeze a snapshot. Returns a tuple of
    (first_method, depth, confidence) records, sorted deterministically so the
    file's insertion order cannot affect results. Missing/unreadable file -> ().
    Never raises."""
    recs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                chain = obj.get("chain", "")
                if not isinstance(chain, str):
                    continue
                steps = [s.split("(", 1)[0].lower().strip()
                         for s in chain.split(" -> ") if s]
                if not steps:
                    continue
                try:
                    conf = float(obj.get("confidence", 0.0))
                except (TypeError, ValueError):
                    conf = 0.0
                recs.append((steps[0], max(len(steps) - 1, 0), conf))
    except OSError:
        return ()
    recs.sort(key=lambda r: (r[0], r[1], r[2]))
    return tuple(recs)


def snapshot_digest(recs: tuple) -> str:
    """Pinned canonical digest of a snapshot (order/format independent)."""
    h = hashlib.sha256()
    for first, depth, conf in recs:
        h.update(str(first).encode("utf-8") + b"\0"
                 + str(depth).encode("utf-8") + b"\0"
                 + repr(conf).encode("utf-8") + b"\n")
    return h.hexdigest()


def learned_prior_map(recs: tuple, family: str, seed: int = 0) -> dict:
    """Map first-method name -> additive prior boost (0..0.25), derived purely
    from (family, snapshot digest, fixed seed). Deterministic and read-only.
    Only confidently-solved chains (confidence >= floor) contribute, so noise
    never inflates a method."""
    d = snapshot_digest(recs)
    counts: dict = {}
    for first, _depth, conf in recs:
        if conf < _SOLVE_CONFIDENCE_FLOOR:
            continue
        counts[first] = counts.get(first, 0) + 1
    if not counts:
        return {}
    total = sum(counts.values())
    out: dict = {}
    for method, c in counts.items():
        freq = c / total
        boost = min(0.25, 0.04 + freq * 0.3)
        # Deterministic jitter keyed by (method, family, digest, seed) so tie
        # ordering is stable across machines, runs, and file insertion order,
        # and different families never collapse to identical maps.
        jitter = (int.from_bytes(
            hashlib.sha256(f"{method}|{family}|{d}|{seed}".encode("utf-8"))
            .digest()[:4], "big") % 2000) / 100_000.0
        out[method] = round(min(0.25, boost + jitter), 4)
    return out
