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
2026-11-08: reviewer-feedback round — repo restructure (tests/ dir, tools
archived, LICENSE, pyproject.toml, docs/ explainability), honest real-challenge
benchmark vs RsaCtfTool/Ciphey (real_challenges/BENCHMARK.md). Commit 97c0cad
prior; this round pending commit.

## Current task
(empty)

## Backlog
- BKLG-18 [benchmark, low, p5] Provide a Python ≤3.9 env to fill the Ciphey
  comparison gap (cipheycore wheel capped at CPython 3.9; N/A on 3.12).
- BKLG-19 [bugfix, low, p4] rail-fence (picoCTF 2022) missed ("No weakness
  found") — investigate why the rail-fence solver did not engage on
  real_challenges/rail-fence/message.txt.
- BKLG-20 [bugfix, low, p4] Sum-O-Primes (picoCTF 2022) not using the given
  x=p+q leak — solver should consume the labeled `x` value.
- BKLG-21 [verification, low, p4] Very_Smooth p−1: README claims a p−1 solve
  but the benchmark agent's reproducible runs did not recover a flag — confirm
  or correct the claim.
- BKLG-22 [diagnostic, low, p4] test_flaws2 reports 18 p−1/p+1 "flaws" on
  small primes. Verified these are an inherent limit of Pollard p−1 (when BOTH
  p−1 and q−1 are smooth below B, `gcd(2^(B!)-1, n) = n`, so no split; the
  p−1/p+1 method requires exactly one side smooth). Pre-existing — the test
  crashed at HEAD before reaching these checks. Decide: relax the test's
  expectation for both-factors-smooth pairs, or add a split-completeness check.

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
- BKLG-10 [2026-11-08] Removed dead `ctx.grace` / `G1B_GRACE` config: the
  field and its three write sites (env parse at search() start, `=0.0` after
  exact-like decode) had no reader, and `_search_t0` was likewise only ever
  written. Removed the field, the env-parse block, the post-exact write, and
  the now-empty `_search_t0` global, and fixed a duplicate `serial = 0`.
  Verified: no dangling refs; e7 4/4, ui_safety, flagshape, substitution,
  rot13 all pass.
- BKLG-11 [2026-11-08] Added test_playfair_hill_watcher.py: playfair decrypt
  known vectors, playfair encrypt/decrypt round-trip, playfair solver smoke
  (stochastic hillclimber — yields printable candidate, no hardcoded flag),
  hill-2x2 full-enumeration recovery (true key ranked #0 in prefilter), and
  watcher classify api/flagged/other. ALL OK.
- BKLG-12 [2026-11-08] Rewrote test_multijob.py as a thread-pool harness that
  compares -j1 vs -j4 top-3 (chain+plaintext) per fixture, separating
  RUN-ERROR/MISMATCH/SKIP. Now 36/36 equal (previously 34/36 — the two
  mismatches were ec_sample + real_dlp/output.txt, both genuinely unsolved).
- BKLG-15 [2026-11-08] `--json` corruption fixed: all `[verbose]` diagnostic
  prints (solver-time, verified-exact, kept-rows, bug_log) moved to
  sys.stderr. Previously 8 run_tests fixtures failed with JSONDecodeError.
- BKLG-16 [2026-11-08] Fixed pre-existing `UnboundLocalError: match_text`
  crash in core.py: `match_text` was referenced inside the evidence gate
  (`flag_shaped or (recovered and not statistical)`) but only assigned under
  `if flag_match:`. Every recovered-type solver (RSA, EC-DLP, ECDSA, DSA,
  Franklin-Reiter, LCG) crashed and silently dropped its result. Added
  `match_text = ""` default. This was the sole cause of 7 run_tests ERR rows;
  run_tests went 35/43 → 43/43. Verified no regression: blind3/blind4 25/25
  (serial), matrix/flagshape/e3/e4/e7/families/xorfamily/substitution/
  transposition/rot13/base36/b16/hexfamily/affine/rsafamilies/playfair/
  optional/flaws all PASS.
- BKLG-17 [2026-11-08] Added generic small-field `elliptic-curve-dlog`
  solver (parse p/a/b/gx/gy/qx/qy, verify on-curve, BSGS/brute-force over
  the small subgroup; no hardcoded flags) and widened the `dlp-composite-
  smooth` matcher to fire on n+c without an explicit g (base hypothesised).
  Together these make ec_sample (ECC k=7) and real_dlp/output.txt (smooth-
  composite DLP, base 3) recover fully and deterministically — multijob
  36/36, run_tests ecdlp/real_dlp PASS.
- BKLG-18 [2026-11-08] Reviewer-feedback restructure: moved all 34 `test_*.py`
  into `tests/` (git mv + path-bootstrap rewrites: `parents[1]` for
  `Path(__file__).parent` ROOT refs, repo-root for `os.path.dirname` HERE/ROOT,
  `sys.path.insert` for direct solvers importers); moved standalone dev/diag
  tools to `archive_scratch/tools_dev/` (diag, diag_e3, e3_section,
  rsa_battery, watcher, flakecheck, fuzz, session.md, report.md, output.txt)
  with `tests/` bootstrap added to flakecheck/diag; added LICENSE (MIT),
  `pyproject.toml` (description/topics/scripts), `docs/SCORING.md`, and
  `docs/SOLVERS.md` (146-solver catalog); updated run_tests.sh and README paths.
  Verified: `run_tests.sh` 43/43 PASS; full `tests/` suite green.
- BKLG-19 [2026-11-08] Honest real-challenge benchmark (subagent):
  `real_challenges/BENCHMARK.md` compares autocrypt vs RsaCtfTool (installed
  from git) vs Ciphey (N/A — `cipheycore` wheel capped at CPython 3.9). Added
  real challenges substitution0/1/2 and rail-fence (picoCTF 2023/2022). Finds:
  autocrypt wins small-e RSA (incl. Mini_RSA's c+i·n twist RsaCtfTool misses)
  and all three monoalphabetic substitutions; loses on rail-fence and
  Sum-O-Primes (p+q leak unused); Very_Smooth p−1 README claim did not
  reproduce. Caveats logged; nothing fabricated.
