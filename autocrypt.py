#!/usr/bin/env python3
"""Command-line entry point for autocrypt."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from core import Context, fingerprint, search
from scoring import assess
import solvers  # register built-ins


def _params(spec: str) -> dict:
    result = {}
    for item in re.split(r"[,;\s]+", spec.strip()):
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        value = value.strip().replace("_", "").replace(",", "")
        try:
            result[key.lower()] = int(value, 0) if value.lower().startswith("0x") else int(value)
        except ValueError:
            result[key.lower()] = value
    return result


def _read(args):
    """Returns (data, findings, source). Accepts data files and/or challenge .py files."""
    files = [f for f in (args.file or ["-"])]
    if files == ["-"]:
        return sys.stdin.buffer.read(), [], ""
    import challenge
    return challenge.load(files)


def _load_wordlist(path):
    if not path:
        return []
    with open(path, "rb") as f:
        return [line.rstrip(b"\r\n") for _, line in zip(range(100_000), f)]


def solve_data(data, *, flag_format=r"\w{1,40}\{.*?\}", timeout=20.0, top=200,
               known_plaintext="", wordlist_path="", params="", jobs=None,
               progress_callback=None, flag_format_explicit=False, verbose=False,
               strict=False, fast=False, deep=False, max_depth=6):
    """Run the existing fingerprint/search pipeline for both CLI and UI."""
    wordlist = _load_wordlist(wordlist_path)
    fp = fingerprint(data)
    if jobs is None:
        jobs = min(os.cpu_count() or 1, 8)
    jobs = max(1, int(jobs))
    # --fast: 50% shorter per-solver slices and skip the costly brute-force
    # solvers; --deep: 2x per-solver slices and a deeper search.
    speed = 0.5 if fast else (2.0 if deep else 1.0)
    if fast:
        heavy = frozenset({"dlp-composite-smooth", "hill-2x2", "enigma-m3",
                           "hash-crack", "vigenere-brute"})
    else:
        heavy = frozenset()
    if deep:
        max_depth = 9
    ctx = Context(deadline=time.monotonic() + timeout,
                  flag_regex=re.compile(flag_format, re.DOTALL),
                  flag_regex_explicit=flag_format_explicit,
                  known_plaintext=known_plaintext, wordlist=wordlist,
                  rsa_params=_params(params), assess=assess,
                  progress_callback=progress_callback, jobs=jobs,
                  strict=strict or bool(os.environ.get("AUTOCRYPT_STRICT")),
                  speed=speed, heavy_names=heavy)
    ctx.search_t0 = time.monotonic()
    pool = None
    if jobs > 1 and data and len(data) >= 128:
        pool = ProcessPoolExecutor(max_workers=jobs)
        ctx.pool = pool
    import solvers as _solvers
    _exact_res = None
    try:
        _txt = data.decode("utf-8")
    except Exception:
        _txt = ""
    if _txt and ("functools.cache" in _txt or "def " in _txt):
        try:
            _items = list(_solvers.solve_linear_recurrence(data, ctx))
        except Exception:
            _items = []
        if _items:
            from core import SearchResult
            _recs = [{"chain": m, "plaintext": o if isinstance(o, str) else o.decode("utf-8", "replace"),
                      "confidence": s, "is_flag": False, "_reason": "exact linear-recurrence recovery"}
                     for o, m, p, s in _items]
            _exact_res = SearchResult(_recs, "FOUND", ctx.failures)
    if _exact_res is not None:
        res = _exact_res
        if ctx.pool is not None:
            ctx.pool.shutdown(wait=False, cancel_futures=True)
        # skip the full best-first search entirely
        res = _exact_res
    else:
        try:
            res = search(data, ctx, top=top, max_depth=max_depth)
        finally:
            if ctx.pool is not None:
                ctx.pool.shutdown(wait=False, cancel_futures=True)
    if verbose:
        for name, dt in sorted(ctx.solver_times.items(), key=lambda kv: -kv[1])[:12]:
            print(f"[verbose] solver time {name}: {dt:.2f}s")
        if ctx.exact_found:
            print(f"[verbose] verified exact at {ctx.exact_time - ctx.search_t0:.2f}s: {ctx.exact_chain}")
    # Hide low-confidence junk: it only misleads. Flags and exact recoveries
    # always stay. Core already floors genuine plaintext at ~0.62, so anything
    # below 0.60 that is not an exact recovery is a weak guess (short-text note,
    # exhaustive-key relative candidate, or a statistical margin) -- e.g. hill
    # 2x2 / playfair hill-climb noise -- and is not shown.
    def _junk(r):
        if r.get("is_flag"):
            return False
        method = r["chain"].split(" -> ")[-1].lower()
        if any(method.startswith(p) for p in ("cracked ", "rsa ", "jwt hs256",
                                              "diffie-hellman")):
            return False
        return r["confidence"] < .6
    kept = [r for r in res if not _junk(r)]
    if len(kept) != len(res):
        res = type(res)(kept, res.status if kept else "NOT_FOUND", res.failures)
    if verbose:
        for r in res:
            print(f"[verbose] kept: {r['chain']} (confidence {r['confidence']}, "
                  f"flag={r.get('is_flag')}) -- {r.get('_reason', '')}")
    return fp, res, ctx


def build_parser():
    p = argparse.ArgumentParser(
        prog="autocrypt.py",
        description="Fingerprint unknown data and search for common CTF crypto weaknesses.",
    )
    p.add_argument("file", nargs="*", default=["-"],
                   help="input path(s): data .txt and/or the challenge .py (static analysis, never run); - for stdin")
    p.add_argument("--flag-format", default=r"\w{1,40}\{.*?\}", help="regex used for early flag detection")
    p.add_argument("--top", type=int, default=200, help="maximum text results")
    p.add_argument("--timeout", type=float, default=20.0, help="global time budget in seconds")
    p.add_argument("-j", "--jobs", type=int, default=None,
                   help="worker processes (default: min(cpu_count,8); 1 = sequential)")
    p.add_argument("--json", action="store_true", help="emit JSON results (all fields) with status/failures")
    p.add_argument("--explain", action="store_true",
                   help="print a plain-English explanation of each recovery chain layer")
    p.add_argument("--verbose", action="store_true", help="explain why each candidate was accepted or rejected")
    p.add_argument("--strict", action="store_true",
                   help="fail (non-zero exit, after finishing) on unexpected solver exceptions")
    p.add_argument("--wordlist", help="wordlist for hash and JWT-secret cracking")
    p.add_argument("--known-plaintext", default="", help="known plaintext crib")
    p.add_argument("--params", default="", help='RSA parameters, e.g. "n=...,e=...,c=..."')
    p.add_argument("--fast", action="store_true",
                   help="cut time in half: shorter per-solver slices, skip the slowest brute-force solvers")
    p.add_argument("--deep", action="store_true",
                   help="2x per-solver time and deeper search (for stubborn challenges)")
    p.add_argument("--no-color", action="store_true", help="disable terminal colors")
    return p


def main(argv=None):
    # A recovered plaintext may contain bytes that the console codec (e.g.
    # cp1252) cannot encode; replace them instead of crashing the whole run
    # mid-report (seen on invalid U+FFFD in long-lost RSA/FR plaintexts).
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv and sys.stdin.isatty():
        from ui import interactive
        return interactive()
    args = build_parser().parse_args(argv)
    if args.top < 0 or args.timeout <= 0:
        build_parser().error("--top must be nonnegative and --timeout must be positive")
    if args.no_color:
        import ui
        ui.COLOR_ENABLED = False
    try:
        flag_regex = re.compile(args.flag_format, re.DOTALL)
    except re.error as exc:
        build_parser().error(f"invalid --flag-format regex: {exc}")
    try:
        data, notes, source = _read(args)
    except OSError as exc:
        print(f"autocrypt: {exc}", file=sys.stderr)
        return 2

    try:
        fp, results, ctx = solve_data(
            data, flag_format=args.flag_format, timeout=args.timeout, top=args.top,
            known_plaintext=args.known_plaintext, wordlist_path=args.wordlist or "",
            params=args.params, jobs=args.jobs, flag_format_explicit=any(
                arg == "--flag-format" or arg.startswith("--flag-format=") for arg in argv),
            verbose=args.verbose, strict=args.strict,
            fast=args.fast, deep=args.deep,
        )
        if ctx.bug_log:
            for bname, typ, tb in ctx.bug_log:
                line = tb.splitlines()[-1].strip() if tb else ""
                print(f"[verbose] solver {bname} raised {typ}: {line}")
        if ctx.strict and (ctx.strict_failed or any(
                "[BUG" in f for f in ctx.failures)):
            ctx.strict_failed = True
    except KeyboardInterrupt:
        if "ctx" in locals() and ctx.pool is not None:
            ctx.pool.shutdown(wait=False, cancel_futures=True)
        raise
    except OSError as exc:
        print(f"autocrypt: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "status": results.status,
            "failures": results.failures,
            "first_exact": round(ctx.exact_time - ctx.search_t0, 2)
            if getattr(ctx, "exact_found", False) and ctx.exact_time else None,
            "results": [{key: result.get(key) for key in
                         ("chain", "plaintext", "confidence", "is_flag", "_reason")}
                        for result in results],
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 3 if ctx.strict and ctx.strict_failed else 0

    print(f"Fingerprint: {fp['length']} bytes, entropy {fp['entropy']:.3f} bits/byte, "
          f"charset={fp['charset']}, IC={fp['ic']:.4f}")
    if fp["magic"]:
        print("Magic/tells: " + ", ".join(fp["magic"]))
    if fp["hashes"]:
        print("Hash-like fingerprint: " + ", ".join(fp["hashes"]))
    if fp["hypotheses"]:
        print("Encoding hypotheses (prior):")
        for name, prior in fp["hypotheses"]:
            print(f"  {name}: {prior:.2f}")
    for finding in notes:
        print("Challenge: " + finding)
    for finding in dict.fromkeys(ctx.findings):
        print("Finding: " + finding)
    for failure in dict.fromkeys(ctx.failures):
        print("Solver failure: " + failure)

    if not results:
        if results.status == "TIMEOUT":
            print("Timed out. No result was recovered within the time budget.")
        elif results.status == "TOO_SHORT":
            print("Input too short to judge. No result was recovered.")
        elif results.status == "SOLVER_FAILED":
            print("A solver failed or was cut short, so this result is unreliable")
        else:
            print("No weakness found. Looks like properly encrypted or random data.")
        return 3 if ctx.strict and ctx.strict_failed else 0
    print("\nRanked results:")
    for i, result in enumerate(results, 1):
        reason = result["_reason"]
        is_flag = result.get("is_flag", False)
        if is_flag:
            label = " *** FLAG ***"
        elif reason.startswith("LOW CONFIDENCE"):
            label = " LOW CONFIDENCE"
        else:
            label = ""
        print(f"\n{i}. {result['chain']}")
        if args.explain:
            from explain import explain_chain
            for _line in explain_chain(result["chain"]):
                print(f"     └ {_line}")
        if is_flag:
            print(f"   Confidence: {result['confidence']:.2f}{label}")
        else:
            print(f"   Confidence: {result['confidence']:.2f}{label} — {reason}")
        print("   Plaintext:")
        print(result["plaintext"])
    return 3 if ctx.strict and ctx.strict_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
