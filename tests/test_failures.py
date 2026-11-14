"""Phase 1 tests: failure log (failures.jsonl) + --replay.

Covers:
  - record_failure/build_record write a JSONL line with the required fields
    (input_b64, timestamp, decoders_tried, best_score) and round-trip.
  - solve_data logs an undecoded input to the requested path, and does NOT log
    when a plaintext is recovered.
  - --replay reruns logged failures and reports which now pass.
  - iter_failures skips blank/malformed lines.

Run:  PYTHONPATH=. .venv/Scripts/python.exe test_failures.py
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Keep any stray run from polluting the repo root during this test module.
os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"


def _run_cli(args, cwd=None):
    r = subprocess.run([sys.executable, "-m", "autocrypt.cli"] + args,
                       cwd=cwd or str(ROOT), capture_output=True, text=True,
                       timeout=120)
    return r


def test_record_build_and_roundtrip():
    from autocrypt.failures import build_record, record_failure, iter_failures
    data = b"this is undecodable garbage !! \xff\x00\x01"
    class Ctx:
        solver_times = {"base64": 0.1, "xor": 0.3}
    rec = build_record(data, Ctx(), "NOT_FOUND", 0.42,
                       {"chain": "base64", "confidence": 0.42},
                       {"flag_format": r"\w{1,40}\{.*?\}", "timeout": 5,
                        "max_depth": 3, "params": "", "jobs": 1,
                        "charset": "mixed", "known_plaintext": "crib",
                        "wordlist_path": "w.txt", "fast": True,
                        "deep": False, "strict": True})
    assert rec["version"] == 1
    assert rec["length"] == len(data)
    assert rec["input_b64"] == base64.b64encode(data).decode()
    assert base64.b64decode(rec["input_b64"]).decode("latin-1") == data.decode("latin-1")
    assert rec["timestamp"] and "T" in rec["timestamp"]
    assert set(rec["decoders_tried"]) == {"base64", "xor"}
    assert rec["best_score"] == 0.42
    assert isinstance(rec["preview"], str) and rec["preview"]
    # preview truncation: long input collapses to <= limit chars + ellipsis
    long_rec = build_record(b"A" * 200, Ctx(), "NOT_FOUND", 0.0, None,
                            {"flag_format": r"\w+", "timeout": 5,
                             "max_depth": 3, "params": "", "jobs": 1,
                             "charset": "ascii-text"})
    assert len(long_rec["preview"]) <= 81 and long_rec["preview"].endswith("…")
    assert rec["known_plaintext"] == "crib" and rec["wordlist_path"] == "w.txt"
    assert rec["fast"] is True and rec["deep"] is False and rec["strict"] is True
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fail.jsonl"
        record_failure(str(p), rec)
        rows = list(iter_failures(str(p)))
        assert len(rows) == 1
        back = rows[0]
        # full read-back parity for every replay-affecting + diagnostic field
        for key in ("version", "length", "input_b64", "timestamp", "status",
                    "preview", "charset", "best_score", "top_candidate",
                    "flag_format", "timeout", "max_depth", "params", "jobs",
                    "known_plaintext", "wordlist_path", "fast", "deep", "strict"):
            assert key in back, f"record lost field {key}"
            assert back[key] == rec[key], f"field {key} changed in round-trip"
    print("OK  build_record / record_failure / roundtrip")


def test_solve_data_logs_on_failure_only():
    from autocrypt.cli import solve_data
    # Enable logging for this test (the module-level env guard disables it;
    # unset temporarily so record-writing can be observed).
    saved = os.environ.pop("AUTOCRYPT_NO_FAILURES_LOG", None)
    try:
        # Deterministic high-entropy blob: never a statistical false positive.
        import random
        garbage = random.Random(20261113).randbytes(72)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "failures.jsonl"
            _, res, ctx = solve_data(garbage, timeout=4, top=8, jobs=1,
                                     failure_log_path=str(p))
            assert not getattr(ctx, "decoded", False)
            lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
            assert lines, "expected a failure record"
            rec = json.loads(lines[-1])
            assert base64.b64decode(rec["input_b64"]) == garbage
            assert "decoders_tried" in rec and "best_score" in rec
            # success path appends nothing
            good = b"academy{replay_ok}"
            p2 = Path(td) / "ok.jsonl"
            _, res2, ctx2 = solve_data(good, timeout=6, top=8, jobs=1,
                                       failure_log_path=str(p2))
            assert getattr(ctx2, "decoded", True), "as-is flag should decode"
            assert not p2.exists() or not p2.read_text(encoding="utf-8").strip()
    finally:
        if saved is not None:
            os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = saved
    print("OK  solve_data logs only on failure")


def test_replay_reports_passes_and_fails():
    from autocrypt.failures import DEFAULT_FILE
    # Seed a log: one input that will now pass (as-is flag), one that won't.
    # fail_input is a deterministic 1-byte string: it is undecodable (no
    # solver path for a lone 'a'), so replay reliably reports it as [FAIL].
    # (Random bytes were flaky here — occasionally they decode and flip the
    # expected [FAIL] into a [PASS].)
    pass_input = b"academy{replay_now_passes}"
    fail_input = b"a"
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "failures.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            def row(data):
                return {
                    "version": 1, "timestamp": "2026-11-13T00:00:00",
                    "input_b64": base64.b64encode(data).decode(),
                    "length": len(data), "status": "NOT_FOUND",
                    "decoders_tried": ["base64"], "best_score": 0.1,
                    "top_candidate": None, "flag_format": r"\w{1,40}\{.*?\}",
                    "timeout": 8, "max_depth": 4, "params": "", "jobs": 1,
                }
            fh.write(json.dumps(row(pass_input)) + "\n")
            fh.write(json.dumps(row(fail_input)) + "\n")
        r = _run_cli(["--replay", "--failures", str(path)])
        out = r.stdout
        assert r.returncode == 0, r.stderr
        assert "[PASS]" in out
        assert "[FAIL]" in out
        assert "now pass" in out
        # pass row decoded back to the flag
        assert "academy{replay_now_passes}" in out
    print("OK  --replay reports passing and still-failing cases")


def test_iter_failures_skips_garbage():
    from autocrypt.failures import iter_failures
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "mixed.jsonl"
        p.write_text("this is not json\n\n{\"version\": 1, \"status\": \"NOT_FOUND\"}\n[1,2]\n")
        rows = list(iter_failures(str(p)))
        assert len(rows) == 1 and rows[0]["status"] == "NOT_FOUND"
    print("OK  iter_failures skips malformed lines")


def test_iter_failures_tolerates_nonutf8_bytes():
    """A hand-edited log with non-UTF8 bytes must not crash replay (no
    UnicodeDecodeError while scanning); only the corrupted line is skipped."""
    from autocrypt.failures import iter_failures
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bytes.jsonl"
        good = json.dumps({"version": 1, "status": "NOT_FOUND"}).encode()
        p.write_bytes(good + b"\n\xff\xfe\x80\n" + good + b"\n")
        rows = list(iter_failures(str(p)))
        assert len(rows) == 2 and all(r["status"] == "NOT_FOUND" for r in rows)
    print("OK  iter_failures tolerates non-UTF8 bytes")


def test_replay_tolerates_bad_record_fields():
    """One record with a non-numeric timeout must be counted unusable, not
    abort the whole --replay run."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "failures.jsonl"
        # "good" record must reliably still FAIL on replay, so seed it with a
        # deterministic undecodable input (a lone 'a'), not random bytes which
        # occasionally decode and flip the expected [FAIL] into a [PASS].
        good = {"version": 1, "timestamp": "t", "status": "NOT_FOUND",
                "input_b64": base64.b64encode(b"a").decode(),
                "length": 1, "decoders_tried": ["base64"], "best_score": 0.1,
                "flag_format": r"\w{1,40}\{.*?\}", "timeout": 8,
                "max_depth": 4, "params": "", "jobs": 1}
        bad = dict(good)
        bad["timeout"] = "not-a-float"
        badb64 = dict(good)
        badb64["input_b64"] = "!!! not base64 !!!"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(bad) + "\n")
            fh.write(json.dumps(badb64) + "\n")
            fh.write(json.dumps(good) + "\n")
        r = _run_cli(["--replay", "--failures", str(path)])
        # both unusable branches are exercised and counted, not crashes
        assert r.stdout.count("[ERR ]") == 2, r.stdout
        assert "[FAIL]" in r.stdout
        assert "2 unusable" in r.stdout
        assert r.returncode == 1, r.stderr  # bad records -> non-zero exit
    print("OK  replay tolerates bad record fields")


def test_iter_failures_missing_file_yields_nothing():
    from autocrypt.failures import iter_failures
    with tempfile.TemporaryDirectory() as td:
        missing = Path(td) / "does_not_exist.jsonl"
        assert list(iter_failures(str(missing))) == []
    print("OK  iter_failures handles a missing file")


def test_solve_data_oserror_swallowed():
    """A failure_log_path that cannot be opened (an existing directory) must
    not crash solve_data; the OSError is swallowed."""
    from autocrypt.cli import solve_data
    import random
    saved = os.environ.pop("AUTOCRYPT_NO_FAILURES_LOG", None)
    try:
        garbage = random.Random(7).randbytes(72)
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "unwritable.jsonl"
            d.mkdir()  # a directory, not a file -> IsADirectoryError on open
            _, res, ctx = solve_data(garbage, timeout=4, top=8, jobs=1,
                                     failure_log_path=str(d))
            assert not getattr(ctx, "decoded", False)
    finally:
        if saved is not None:
            os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = saved
    print("OK  solve_data swallows OSError on log write")


def test_env_guard_suppresses_log():
    """With AUTOCRYPT_NO_FAILURES_LOG=1, solve_data must NOT append a record
    even when a failure_log_path is supplied."""
    from autocrypt.cli import solve_data
    import random
    os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"
    try:
        garbage = random.Random(11).randbytes(72)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "suppressed.jsonl"
            _, res, ctx = solve_data(garbage, timeout=4, top=8, jobs=1,
                                     failure_log_path=str(p))
            assert not getattr(ctx, "decoded", False)
            assert not p.exists(), "log should be suppressed by env guard"
    finally:
        os.environ.pop("AUTOCRYPT_NO_FAILURES_LOG", None)
    print("OK  AUTOCRYPT_NO_FAILURES_LOG suppresses logging")


def main():
    test_record_build_and_roundtrip()
    test_solve_data_logs_on_failure_only()
    test_replay_reports_passes_and_fails()
    test_iter_failures_skips_garbage()
    test_iter_failures_tolerates_nonutf8_bytes()
    test_replay_tolerates_bad_record_fields()
    test_iter_failures_missing_file_yields_nothing()
    test_solve_data_oserror_swallowed()
    test_env_guard_suppresses_log()
    print("FAILURES: ALL OK")


if __name__ == "__main__":
    main()
