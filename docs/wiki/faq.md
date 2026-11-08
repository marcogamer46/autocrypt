# Frequently asked questions

Welcome. autocrypt is a command-line CTF crypto auto-solver: you hand it an unknown blob (or a challenge `.py` plus its captured output), and it fingerprints the data, runs a best-first layered decode search over a registry of classical ciphers, encodings, and exact math attacks, and ranks the surviving plaintext candidates. This page answers the common questions newcomers ask.

## What is a CTF?

CTF stands for **capture the flag**. A CTF is a computer-security competition where every challenge hides a secret string — the "flag" — that you must recover. Flags usually look like a wrapper plus a short body, e.g. `flag{...}` or `academy{...}`.

Crypto challenges in a CTF ship a generator script and the encrypted output. You are meant to figure out which cipher or encoding was used and invert it to reveal the flag. autocrypt automates that pipeline for you.

## Why is output deterministic?

You get the same answers no matter how busy the machine is. The search is **time-bounded** and uses **fixed work budgets**:

- Per-solver time slices default to 4 seconds, with at most one 2x extension if the global deadline has room.
- Deterministic work such as key-space enumeration runs to a fixed iteration budget, so results do not change when the machine is loaded.
- After a verified exact recovery, the search drains at most 8 more nodes and stops spawning new expansions.

The result is load-independent output: the same input and flags produce the same ranking every run. The `test_multijob.py` suite even confirms identical top-3 results when running with 1 worker vs 4 workers.

## How does it choose which cipher to try?

In three stages:

1. **Fingerprint** — cheap structural stats: charset, length, entropy, index of coincidence, magic bytes, and regex-based encoding classes (hex, base64/base32, binary, octal, ...).
2. **Best-first search** — each solver declares a `matches(fp)` prior in `[0,1]`. Non-zero priors are scheduled in a priority heap; higher priors run earlier. Deep decoder chains get a gentle depth boost so they aren't starved by shallow guesses.
3. **Free fixpoint pre-pass** — unambiguous whole-buffer decodings (hex/base64/base32/binary, including separator-tolerant hex) are stripped for free before the graph search, so pure encoding stacks don't consume node budget.

A solver is a generator that yields `(plaintext, method, params, claimed_score)` candidates; each is scored for English evidence and flag plausibility, and verified exact recoveries (RSA attacks, crib-based crackings, direct decodes) rank above statistical guesses. See [solver families](solvers.md) and [how results are scored](scoring.md) for the details.

## Does it ever hardcode flags?

No. The ethos is that results are **algorithmic** — flags are never hardcoded into solvers. Real curated challenges read their flag from a `flag.txt`; synthetic fixtures use flags explicitly marked as such and the flag is never shipped inside a pair. When autocrypt recovers a flag, it recovers it by actually decoding or attacking the ciphertext, not by looking it up.

## What can't it do?

autocrypt is honest about its edges. From the README's [Known limits](../../README.md#known-limits) section:

- **Modern authenticated encryption / large-RSA general factoring** are out of scope.
- **Generic semiprimes beyond ~192-bit** (where the built-in p−1/p+1/rho/ECM are practical) are not factored; such inputs need an external QS/GNFS tool.
- **4–5-byte repeating-key XOR over ~20-char flags** is inherently ambiguous; the family target is 7/10 accepted, with the rest honest non-solves.
- **Source-hint propagation** beyond the current static AST extraction (e.g. key material hidden inside challenge `.py`) is a planned next step.

The live tracker `things_it_cant_solve.txt` records unsolved inputs and the root-cause analysis for each.

## How do I update autocrypt?

Run:

```
autocrypt --update
```

(`-update`, single-dash, is an alias.) The updater detects how the install was created (a git checkout, the installer-written `autocrypt.json`, or a pip vcs/archive install). For a git checkout it runs `git fetch` + `git pull --ff-only` and reinstalls if needed. It **refuses to run on a dirty working tree** — commit or stash first. Only non-destructive commands are ever executed.

## How do I uninstall?

Delete `~/.autocrypt` (`%USERPROFILE%\.autocrypt` on Windows), remove the PATH entries the installer added, and optionally `pip uninstall autocrypt`. Both installers print exact uninstall instructions when they finish.

## How can I contribute?

- **Tests** — regression suites live in `tests/` and run from the repo root with the repo's own interpreter (`python3 tests/test_matrix.py --both`, etc.). Add a `test_*` case for anything you touch; add a `run_tests.sh` row if you have a deterministic expected flag.
- **Wiki** — this wiki (`docs/wiki/`) is the newcomer-facing documentation. Improve it, cross-link the outer docs, and keep it grounded in real behavior.
- **Adding a solver** — write one function in a `solvers*.py` file decorated with `@solver(name, matches)`. `matches(fp)` returns a prior; `solve(data, ctx)` yields candidates. Score honestly: a verified recovery may claim high confidence, a statistical guess should not (set `_statistical`). The full how-to is in [SOLVERS.md](../SOLVERS.md).

## Where do the other docs live?

- [SOLVERS.md](../SOLVERS.md) — catalog of all 146 registered solvers, module map, and the add-a-solver contract.
- [SCORING.md](../SCORING.md) — how candidate plaintexts are scored and ranked (English evidence, flag-plausibility, trust tiers).
- [BENCHMARK.md](../../real_challenges/BENCHMARK.md) — honest, held-out benchmark of autocrypt vs RsaCtfTool/Ciphey on real CTF challenges.
- This wiki's own pages: [Command-line reference](cli.md), [Solver families](solvers.md), [How results are scored](scoring.md).
