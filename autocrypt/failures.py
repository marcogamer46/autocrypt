"""Persistent failure log for undecoded inputs (Phase 1).

When a search ends without recovering any plaintext, a single JSON object per
run is appended (one line) to a JSONL file (default ``failures.jsonl``). The
``--replay`` CLI flag reads that file, reruns every logged input through the
normal pipeline, and reports which ones now decode.

The log is faithful enough to reproduce the original run: the raw input is
stored base64-encoded, and the decode-affecting parameters that are recorded
(flag format regex, timeout, max depth, RSA params, worker count, known
plaintext crib, wordlist path, fast/deep/strict) are carried back into the
replay rerun, alongside the diagnostic fields (timestamp, decoders tried, best
score reached).
"""
from __future__ import annotations

import base64 as _b64
import json as _json
import os as _os
import time as _time

DEFAULT_FILE = "failures.jsonl"


def _now_iso() -> str:
    """Local-time ISO timestamp with sub-second precision."""
    ts = _time.time()
    base = _time.strftime("%Y-%m-%dT%H:%M:%S", _time.localtime(ts))
    ms = f"{ts % 1.0:.3f}"[1:]  # ".NNN"
    return base + ms


def _preview(data: bytes, limit: int = 80) -> str:
    """Short printable excerpt of the input for quick human identification."""
    txt = ""
    try:
        txt = data.decode("utf-8", "replace")
    except Exception:
        txt = ""
    flat = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "?"
                    for ch in txt)
    if len(flat) > limit:
        flat = flat[:limit] + "…"
    return flat


def build_record(data: bytes, ctx, status: str, best_score: float,
                 top_candidate, payload: dict) -> dict:
    """Assemble one failure-log record.

    ``ctx`` contributes the decoders that were actually attempted (its
    ``solver_times`` dict). ``payload`` carries the replay-affecting parameters
    (flag_format, timeout, max_depth, params, jobs, charset).
    """
    tried = sorted(getattr(ctx, "solver_times", {}) or {})
    return {
        "version": 1,
        "timestamp": _now_iso(),
        "input_b64": _b64.b64encode(data).decode("ascii"),
        "length": len(data),
        "preview": _preview(data),
        "charset": payload.get("charset", ""),
        "status": status,
        "decoders_tried": tried,
        "best_score": round(float(best_score), 4),
        "top_candidate": top_candidate,
        "flag_format": payload.get("flag_format", r"\w{1,40}\{.*?\}"),
        "timeout": payload.get("timeout", 20.0),
        "max_depth": payload.get("max_depth", 6),
        "params": payload.get("params", ""),
        "jobs": payload.get("jobs"),
        "known_plaintext": payload.get("known_plaintext", ""),
        "wordlist_path": payload.get("wordlist_path", ""),
        "fast": bool(payload.get("fast", False)),
        "deep": bool(payload.get("deep", False)),
        "strict": bool(payload.get("strict", False)),
    }


def record_failure(path: str, rec: dict, *, mode: str = "a") -> None:
    """Append one JSON line to ``path`` (expanding ``~``)."""
    p = _os.path.expanduser(path)
    with open(p, mode, encoding="utf-8") as fh:
        fh.write(_json.dumps(rec, ensure_ascii=False) + "\n")


def iter_failures(path: str):
    """Yield parsed records from ``path``, skipping blank/malformed lines.

    A missing file yields nothing (not an error). Records are data, never
    instructions: keys are read but never executed.
    """
    p = _os.path.expanduser(path)
    try:
        # Non-UTF8 bytes in a hand-edited log must not abort replay: decode
        # them lossily (replacement chars), so the bad line is just skipped as
        # malformed JSON rather than raising UnicodeDecodeError during scan.
        fh = open(p, encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = _json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield rec
