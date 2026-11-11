#!/usr/bin/env python3
"""
automcher.py — Claude Code watchdog.

Watches a `claude --continue` session. When the session exits:

  * cause == "api"/"flagged"  -> automatically restart (`claude --continue`)
                                  immediately, and reset the wake-up counter.
  * cause == "other"           -> wake the session up by sending a "continue"
                                  chat message, up to MAX_WAKEUPS times in a row.
  * after MAX_WAKEUPS wake-ups that did not keep the session going -> hard restart.

Usage:
    python watcher.py                 # use default claude command
    python watcher.py --cmd "fcc-claude" --continue
    python watcher.py --max-wakeups 3 --timeout 600
"""

import argparse
import os
import re
import subprocess
import sys
import time

# ---------------------------------------------------------------- defaults ----
DEFAULT_CMD = "claude"
MAX_WAKEUPS = 3
WAKE_MESSAGE = "continue working on the current task"

# Patterns that indicate the run died because of an API / platform / flag issue.
# (something we can legitimately "just retry"). Everything else is "other".
API_ERROR_PATTERNS = [
    r"\b429\b",
    r"\brate[_ -]?limit",
    r"\bapi[_ -]?error",
    r"\banthropic[_ -]?error",
    r"\bupstream[_ -]?request[_ -]?failed",
    r"\boverloaded",
    r"\bover[_ -]?quota",
    r"\bpayment[_ -]?required",
    r"\bbilling",
    r"\bcredit[_ -]?balance",
    r"\binsufficient[_ -]?credit",
    r"\bquota",
    r"\bflagged\b",
    r"\bmoderation",
    r"\babuse",
    r"\bauthentication[_ -]?error",
    r"\binvalid[_ -]?x-api-key",
    r"\b401\b",
    r"\b403\b",
    r"\b503\b",
    r"\b529\b",
    r"\btimeout",
    r"\bconnection[_ -]?(error|reset|refused)",
    r"\bnetwork[_ -]?error",
]

API_RE = re.compile("|".join(f"(?:{p})" for p in API_ERROR_PATTERNS), re.IGNORECASE)


# ------------------------------------------------------------- classification ----
def classify(run_output: str) -> str:
    """Return 'api' | 'flagged' | 'other'."""
    if not run_output:
        return "other"
    low = run_output.lower()
    if API_RE.search(low):
        # 'flagged' is a distinct sub-cause but we treat both the same:
        return "flagged" if "flagged" in low else "api"
    return "other"


def run_once(cmd: list, timeout: int) -> tuple[int, str]:
    """Run the claude command; return (exit_code, combined_output)."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            return -1, out + "\n[timeout]"
        return proc.returncode, out
    except FileNotFoundError:
        return -2, f"[error] command not found: {cmd[0]}"


def wake_up(cmd: list, timeout: int) -> int:
    """Send a 'continue' chat message into the session (a soft wake-up)."""
    wake_cmd = cmd + ["--continue"]
    try:
        proc = subprocess.Popen(
            wake_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        proc.communicate(input=WAKE_MESSAGE + "\n", timeout=timeout)
        return proc.returncode or 0
    except subprocess.TimeoutExpired:
        # The child is still alive after the timeout; kill it so we don't
        # leak a wedged session process.
        try:
            proc.kill()
            proc.wait()
        except Exception:  # noqa: BLE001
            pass
        print("[watcher] wake_up timed out; killed child session", flush=True)
        return -1
    except Exception as e:  # noqa: BLE001
        print(f"[watcher] wake_up failed: {e}", flush=True)
        return -1


def run(cmd: list, max_wakeups: int, timeout: int) -> None:
    wakeups = 0
    cycle = 0
    while True:
        cycle += 1
        print(f"\n[watcher] cycle {cycle}: starting {cmd}", flush=True)
        code, out = run_once(cmd, timeout)
        cause = classify(out)
        print(
            f"[watcher] exited code={code} cause={cause} "
            f"(wakeups_in_a_row={wakeups})",
            flush=True,
        )

        if cause in ("api", "flagged"):
            print("[watcher] API/flag issue -> automatic restart.", flush=True)
            wakeups = 0
            continue  # immediately loop and restart

        # "other" error -> wake up via chat, at most max_wakeups times.
        if wakeups < max_wakeups:
            wakeups += 1
            print(f"[watcher] other error -> wake-up {wakeups}/{max_wakeups}.", flush=True)
            wake_up(cmd, timeout)
            continue

        print(f"[watcher] {max_wakeups} wake-ups with no progress -> hard restart.", flush=True)
        wakeups = 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Claude Code watchdog")
    ap.add_argument("--cmd", default=DEFAULT_CMD, help="claude binary/alias")
    ap.add_argument("--continue", dest="cont", action="store_true", help="resume session")
    ap.add_argument("--max-wakeups", type=int, default=MAX_WAKEUPS)
    ap.add_argument("--timeout", type=int, default=3600,
                    help="per-run timeout in seconds (default 3600)")
    args = ap.parse_args()

    cmd = [args.cmd]
    if args.cont:
        cmd.append("--continue")

    print(f"[watcher] cmd={cmd} max_wakeups={args.max_wakeups} timeout={args.timeout}", flush=True)
    try:
        run(cmd, args.max_wakeups, args.timeout)
    except KeyboardInterrupt:
        print("\n[watcher] stopped by user.", flush=True)


if __name__ == "__main__":
    main()
