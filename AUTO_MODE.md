# AUTO_MODE.md — autonomous operation manifest

This file is the runbook for unattended (auto-mode) sessions. It is the
single source of truth an agent consults each wakeup to decide what to do
next, and it records what has been done so work never repeats.

## Loop (per wakeup)
1. Refresh the watchdog heartbeat (`touch .watchdog_heartbeat`).
2. Read this file. If the **Current task** is empty, pop the top entry
   from **Backlog** (lowest `priority` number first, then FIFO) into
   `Current task` and mark it `IN PROGRESS`.
3. Execute the task. Keep changes small, tested, and committed with the
   standard attribution line.
4. On success, move the task to **Done** with a one-line outcome; clear
   `Current task`. Update `Last activity`.
5. If a task is blocked (needs a decision, a key, or external data),
   return it to the backlog with a `blocked` note and pick the next.
6. Commit any manifest changes. Schedule the next wakeup (long cadence,
   e.g. 20–30 min) unless a governed notification is pending.

## Ground rules
- Never hardcode solve flags; every solve must be generic/algorithmic.
- Prefer committing small, verified increments over big speculative rewrites.
- If a task runs > ~30 min, stop, commit progress, and requeue the rest.
- Keep LOGS.md and things_it_cant_solve.txt truthful and current.

## Last activity
2026-11-08: auto-mode-setup workflow generated this manifest (wt03ullre).
Batch items already solved/underdetermined are annotated below; the open
work is code-quality (pool scheduling, tests, budget edges, CLI flags).

## Current task
(empty)

## Backlog
- BKLG-01 [bugfix, high, p1] Rework pooled-executor scheduling: per-solver
  deadlines reach workers, `.result()` timeouts, `--fast` skip before
  submission. target: core.py:601-674.
- BKLG-02 [test, medium, p1] Add regression tests guarding UI encode-safety,
  results_panel preview, timeout-invariance. target: ui.py.
- BKLG-03 [test, medium, p1] Repair/determinize test_flaws.py / test_flaws2.py
  (Windows-relative paths, seeding, monotonic clock). target: test_flaws2.py.
- BKLG-09 [bugfix, low, p3] Honor `--no-color` in ui._color_on.
  target: autocrypt.py:164, ui.py:21.
- BKLG-10 [cleanup, low, p3] Wire up or remove ctx.grace / G1B_GRACE
  dead config. target: core.py:516-519,1148.
- BKLG-11 [test, medium, p3] Add playfair + hill-2x2 + watcher regression tests.
  target: solvers.py, watcher.py.
- BKLG-12 [test, high, p3] Harden/speed test_multijob.py (fewer subprocesses,
  mismatch diagnostics, no None-osrun-as-mismatch).
  target: test_multijob.py.
- BKLG-14 [cleanup, low, p4] Purge scratch/unreferenced artifacts after
  verifying each target (keep-list + active-process checks). target: scratch_*.

## Resolved or underdetermined (from prior work — do not re-open)
- BKLG-05 → SOLVED (substitution-wordlist solver recovered flag + study guide).
- BKLG-08 → SOLVED (block-transposition solver recovered msg6213 flag).
- BKLG-13 → SOLVED (rail fence rails=4 + rot13 academy recovered).
- BKLG-06 → UNDERDETERMINED (multiset proof: caldfow cannot map to an
  academy prefix under any classical letter transform; needs generator's key).
- BKLG-07 → UNDERDETERMINED (22 distinct ints vs repeating-letter plaintext;
  needs stateful/OTP key).

## Done
- BKLG-01 [2026-11-08] Pooled-executor scheduling fixed: hoisted --fast
  heavy-solver skip before pool submission; .result() now wait-bounded by
  the remaining global budget (TimeoutError = budget cutoff, not a blocker).
  Verified: test_e7 4/4, test_matrix, test_flagshape pass; jobs=1 vs jobs=4
  determinism MATCH on a pool-triggering input.
- BKLG-02 [2026-11-08] Added test_ui_safety.py: verdict_banner self-safe
  with non-cp1252 flags; results_panel preview/truncation/notes; all panels
  render under reconfigured cp1252 stdout; timeout-invariance top-1 stable
  t=10 vs 20. 4/4 pass.
- BKLG-03 [2026-11-08] Repaired test_flaws.py / test_flaws2.py: replaced
  hardcoded Linux paths in test_flaws2.py with Path(__file__).parent-relative
  imports; switched all deadlines/timers from time.time() to
  time.monotonic() (matches Context.expired); seeded RNG for determinism.
  Full test_flaws.py now runs on Windows: 0 flaws; smoke of both OK.
- BKLG-04 [2026-11-08] Fixed budget-cutoff edges. (1) core.py adaptive
  extension no longer `continue`s (dropping) the boundary candidate when the
  per-solver slice is extended — it falls through and processes that yield
  too. (2) solvers._parallel_map clamps the pool wait to a remaining time
  that is <= 0: it terminates the pool and returns [] cleanly instead of
  passing a non-positive timeout to map_async().get() (which raises soft  Verified: e7 4/4, matrix, flagshape, ui_safety pass; dlp512 determinism
  jobs=1 vs 4 MATCH; timeout-invariance top-1 stable t=10 vs 40.
- BKLG-09 [2026-11-08] `--no-color` now actually disables ANSI: added
  ui.COLOR_ENABLED module toggle (None=auto, False=off, True=on) consulted by
  _color_on(), and autocrypt.py sets it False when --no-color is passed.
  Added regression test test_no_color_flag_disables_ansi. ui_safety 5/5 pass.
