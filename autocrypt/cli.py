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

from autocrypt.core import Context, fingerprint, search
from autocrypt.scoring import assess
from autocrypt._version import __version__ as _version
from autocrypt.failures import DEFAULT_FILE, build_record, record_failure
from autocrypt.failures import iter_failures as _iter_failures
import autocrypt.solvers  # register built-ins


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
    import autocrypt.challenge as challenge
    return challenge.load(files)


def _load_wordlist(path):
    if not path:
        return []
    with open(path, "rb") as f:
        return [line.rstrip(b"\r\n") for _, line in zip(range(100_000), f)]


def solve_data(data, *, flag_format=r"\w{1,40}\{.*?\}", timeout=20.0, top=200,
               known_plaintext="", wordlist_path="", params="", jobs=None,
               progress_callback=None, flag_format_explicit=False, verbose=False,
               strict=False, fast=False, deep=False, max_depth=5,
               failure_log_path=None, beam_width=None, key="", profile="flag"):
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
    from autocrypt.scoring import get_assessor
    ctx = Context(deadline=time.monotonic() + timeout,
                  flag_regex=re.compile(flag_format, re.DOTALL),
                  flag_regex_explicit=flag_format_explicit,
                  known_plaintext=known_plaintext, wordlist=wordlist,
                  rsa_params=_params(params), assess=get_assessor(profile),
                  profile=profile, progress_callback=progress_callback, jobs=jobs,
                  strict=strict or bool(os.environ.get("AUTOCRYPT_STRICT")),
                  speed=speed, heavy_names=heavy,
                  beam_width=beam_width if beam_width is not None else 64,
                  key=key)
    ctx.search_t0 = time.monotonic()
    pool = None
    if jobs > 1 and data and len(data) >= 128:
        pool = ProcessPoolExecutor(max_workers=jobs)
        ctx.pool = pool
    import autocrypt.solvers as _solvers
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
            from autocrypt.core import SearchResult
            _recs = [{"chain": m, "plaintext": o if isinstance(o, str) else o.decode("utf-8", "replace"),
                      "confidence": s, "is_flag": False, "_reason": "exact linear-recurrence recovery"}
                     for o, m, p, s in _items]
            _exact_res = SearchResult(_recs, "FOUND", ctx.failures)
            # Mirror the main search loop's exact-recovery bookkeeping so the
            # JSON `first_exact` field and --verbose "verified exact" line work
            # on this fast path too.
            ctx.exact_found = True
            ctx.exact_time = time.monotonic()
            ctx.exact_chain = _recs[0]["chain"] if _recs else ""
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
            print(f"[verbose] solver time {name}: {dt:.2f}s", file=sys.stderr)
        _st = getattr(ctx, "stats", {})
        print(f"[verbose] beam width={getattr(ctx, 'beam_width', 3)} "
              f"nodes_expanded={_st.get('nodes_expanded')} "
              f"children_pushed={_st.get('children_pushed')} "
              f"transforms_run={_st.get('transforms_run')} "
              f"per_depth={sorted(_st.get('per_depth', {}).items())}",
              file=sys.stderr)
        if ctx.exact_found:
            print(f"[verbose] verified exact at {ctx.exact_time - ctx.search_t0:.2f}s: {ctx.exact_chain}",
                  file=sys.stderr)
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
    _prefilter = list(res)
    best_score = max((float(r.get("confidence", 0.0)) for r in _prefilter),
                     default=0.0)
    top_candidate = None
    if _prefilter:
        _best_row = max(_prefilter, key=lambda r: float(r.get("confidence", 0.0)))
        top_candidate = {"chain": _best_row["chain"],
                         "confidence": round(float(_best_row.get("confidence", 0.0)), 4)}
    if len(kept) != len(res):
        # Preserve TIMEOUT / SOLVER_FAILED signals rather than erasing them
        # when junk-filtering empties the results (previously everything was
        # flattened to NOT_FOUND, hiding that the run timed out or a solver
        # failed).
        new_status = res.status if kept else (
            res.status if res.status in ("TIMEOUT", "SOLVER_FAILED") else "NOT_FOUND")
        res = type(res)(kept, new_status, res.failures)
    ctx.decoded = bool(kept)
    # Phase 1 failure log: when an input could not be decoded, append one JSONL
    # record (input, timestamp, decoders tried, best score) so --replay can
    # rerun it later. Skipped for empty input and under the test harness
    # (AUTOCRYPT_NO_FAILURES_LOG=1) so suites don't pollute the repo.
    if failure_log_path and not ctx.decoded and data \
            and os.environ.get("AUTOCRYPT_NO_FAILURES_LOG") != "1":
        try:
            rec = build_record(data, ctx, res.status, best_score, top_candidate, {
                "flag_format": flag_format, "timeout": timeout,
                "max_depth": max_depth, "params": params, "jobs": jobs,
                "charset": fp.get("charset", ""),
                "known_plaintext": known_plaintext,
                "wordlist_path": wordlist_path,
                "fast": fast, "deep": deep, "strict": strict})
            record_failure(failure_log_path, rec)
        except OSError:
            pass
    if verbose:
        for r in res:
            print(f"[verbose] kept: {r['chain']} (confidence {r['confidence']}, "
                  f"flag={r.get('is_flag')}) -- {r.get('_reason', '')}",
                  file=sys.stderr)
    return fp, res, ctx


def build_parser():
    p = argparse.ArgumentParser(
        prog="autocrypt",
        description="Fingerprint unknown data and search for common CTF crypto weaknesses.",
    )
    p.add_argument("file", nargs="*", default=["-"],
                   help="input path(s): data .txt and/or the challenge .py (static analysis, never run); - for stdin")
    p.add_argument("--flag-format", default=r"\w{1,40}\{.*?\}", help="regex used for early flag detection")
    p.add_argument("--top", type=int, default=200,
                   help="number of ranked results to report (default 200)")
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
    p.add_argument("--beam-width", type=int, default=64,
                   help="max children expanded per search node (beam width); default 64")
    p.add_argument("--profile", default="flag", choices=["flag", "token", "readable", "none"],
                    help="scoring profile: flag (English+flag-shape, default), token "
                         "(structural/code), readable (lenient), none (no language scoring)")
    p.add_argument("--key", default="",
                   help="known cipher key (e.g. a Vigenère keyword); blank = crack automatically")
    p.add_argument("--failures", metavar="PATH",
                   help="JSONL log of undecoded inputs (default: failures.jsonl); also read by --replay")
    p.add_argument("--replay", action="store_true",
                   help="rerun every logged failure and report which now decode")
    p.add_argument("--no-color", action="store_true", help="disable terminal colors")
    p.add_argument("--update", "-update", action="store_true",
                   help="self-update: pull latest code from the git repo this install was made from and reinstall into the active virtualenv")
    p.add_argument("--version", action="version",
                   version=f"autocrypt {_version}")
    return p


def _self_update():
    """Self-update used by --update, delegated to autocrypt.updater.

    The updater dispatches on how this install was created (git checkout,
    installer-created venv via <venv>/autocrypt.json, or pip-installed from
    GitHub), refuses to touch a dirty working tree in git mode, and never runs
    destructive commands.
    """
    from autocrypt.updater import do_update
    return do_update()


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
        from autocrypt.ui import interactive
        return interactive()
    args = build_parser().parse_args(argv)
    if args.update:
        return _self_update()
    if args.top < 0:
        build_parser().error(f"--top must be nonnegative (got {args.top})")
    if args.timeout <= 0:
        build_parser().error(f"--timeout must be positive (got {args.timeout})")
    if args.no_color:
        import autocrypt.ui as ui
        ui.COLOR_ENABLED = False
    if args.replay:
        # --replay: rerun every logged failure and report which now decode.
        rpath = args.failures or DEFAULT_FILE
        entries = list(_iter_failures(rpath))
        total = len(entries)
        passed = still_failed = bad = 0
        print(f"Replay: {total} logged failure(s) from {rpath}")
        for i, rec in enumerate(entries, 1):
            try:
                import base64 as _b64
                data_r = _b64.b64decode(rec["input_b64"], validate=True)
                flagf = rec.get("flag_format", r"\w{1,40}\{.*?\}")
                tout = float(rec.get("timeout", 20.0))
                md = int(rec.get("max_depth", 6))
                paras = rec.get("params", "")
                crib = rec.get("known_plaintext", "")
                wl = rec.get("wordlist_path", "") or None
                fast_r = bool(rec.get("fast", False))
                deep_r = bool(rec.get("deep", False))
                strict_r = bool(rec.get("strict", False))
            except Exception:
                bad += 1
                print(f"[ERR ] #{i}: unusable record (bad input/fields)")
                continue
            try:
                _fp, _res, _ctx = solve_data(
                    data_r, flag_format=flagf, timeout=tout, top=8,
                    known_plaintext=crib, wordlist_path=wl,
                    params=paras, jobs=1, max_depth=md,
                    fast=fast_r, deep=deep_r, strict=strict_r,
                    failure_log_path=None)
            except Exception as exc:
                bad += 1
                print(f"[ERR ] #{i}: exception {type(exc).__name__}: {exc}")
                continue
            if getattr(_ctx, "decoded", False) and _res:
                passed += 1
                top = _res[0]
                txt = str(top.get("plaintext") or "")[:120]
                print(f"[PASS] #{i}: {top['chain']} "
                      f"({float(top['confidence']):.2f}) {txt!r}")
            else:
                still_failed += 1
                print(f"[FAIL] #{i}: still undecoded (status={_res.status})")
        print(f"\nReplay result: {passed} now pass, {still_failed} still fail, "
              f"{bad} unusable record(s), {total} total.")
        return 1 if bad else 0
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
            failure_log_path=args.failures or DEFAULT_FILE,
            beam_width=args.beam_width,
            key=args.key,
            profile=args.profile,
        )
        if ctx.bug_log:
            for bname, typ, tb in ctx.bug_log:
                line = tb.splitlines()[-1].strip() if tb else ""
                print(f"[verbose] solver {bname} raised {typ}: {line}", file=sys.stderr)
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
            "elapsed_seconds": round(time.monotonic() - ctx.search_t0, 3),
            "solver_times": {name: round(dt, 3) for name, dt in sorted(
                ctx.solver_times.items(), key=lambda kv: -kv[1])},
            "search_stats": {k: (dict(v) if isinstance(v, dict) else v)
                             for k, v in getattr(ctx, "stats", {}).items()},
            "first_exact": round(ctx.exact_time - ctx.search_t0, 2)
            if getattr(ctx, "exact_found", False) and ctx.exact_time else None,
            "fingerprint": {
                "length": fp["length"],
                "entropy": round(fp["entropy"], 4),
                "charset": fp["charset"],
                "ic": round(fp["ic"], 4),
                "classes": fp["classes"],
                "magic": fp["magic"],
                "hashes": fp["hashes"],
                "hypotheses": [[name, prior] for name, prior in fp["hypotheses"]],
            },
            "notes": list(notes),
            "findings": list(dict.fromkeys(ctx.findings)),
            "results": [],
        }
        for result in results:
            r = {key: result.get(key) for key in
                 ("chain", "plaintext", "confidence", "is_flag", "_reason")}
            if args.explain:
                from autocrypt.explain import explain_chain
                r["explanation"] = list(explain_chain(result["chain"]))
            payload["results"].append(r)
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
            from autocrypt.explain import explain_chain
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
