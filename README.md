# autocrypt

A CLI CTF crypto auto-solver. Given an unknown blob (or a challenge `.py` +
captured output), it fingerprints the data and runs a best-first layered decode
search over a registry of classical ciphers, encodings, and exact math attacks,
then ranks the surviving plaintext candidates.

Built and tested for Python 3.12+ (stdlib only; optional crypto libs are never
required and never executed).

## Documentation

- **[Wiki — read & understand the project](docs/wiki/index.md)** — a
  beginner-friendly hub: overview, quickstart, how it works, CLI reference,
  developer guide, and FAQ.
- [`docs/SCORING.md`](docs/SCORING.md) — how candidate plaintexts are scored
  and ranked (English evidence, flag-plausibility, trust tiers).
- [`docs/SOLVERS.md`](docs/SOLVERS.md) — catalog of all 146 registered solvers,
  with the module map and how priorities are set.
- [`real_challenges/BENCHMARK.md`](real_challenges/BENCHMARK.md) — honest,
  held-out benchmark of autocrypt vs RsaCtfTool/Ciphey on real CTF challenges.

## Design overview

### Pipeline

```
input -> fingerprint(data) -> best-first layered decode search (autocrypt/core.py)
         -> solver registry (autocrypt/solvers*.py)
         -> candidate records (chain, plaintext, confidence, trust)
         -> rank + display (autocrypt/ui.py, autocrypt/cli.py)
```

1. **Fingerprint** (`core.fingerprint`): cheap structural stats — charset,
   length, entropy, index of coincidence, magic bytes, and regex-based encoding
   classes (hex, base64/base32, binary, octal, …). The `prior_map` drives which
   solvers get scheduled.
2. **Best-first search** (`core.search`): a priority heap of decode nodes.
   Each node is a byte blob plus a chain of transforms that produced it.
   Priorities combine the chain prior, fingerprint prior, and the score of the
   decode that created the node. Deep decoder chains get a gentle depth boost so
   they are not starved by shallow guesses.
3. **Free fixpoint pre-pass** (`core._free_fixpoint`): unambiguous whole-buffer
   decodings (hex/base64/base32/binary, including separator-tolerant hex) are
   stripped for free before the graph search, so pure encoding stacks do not
   consume node budget.
4. **Solver registry** (`@solver(name, matches)` decorator): each solver
   declares a `matches(fp)` prior and a generator `solve(data, ctx)` that yields
   `(plaintext, method, params, claimed_score)`. New solvers are added by
   writing one function + prior.
5. **Scoring/ranking** (`scoring.py`, `core.py`): per-candidate evidence =
   English quadgrams + dictionary-word fraction, leet-body dictionary fraction
   for flag-shaped outputs, and consistency checks for fixed substitutions.
   Rows carry a trust tier; verified exact recoveries (RSA attacks, crib-based
   crackings, direct decodes) are kept above speculative statistics.
6. **Time/load robustness**: per-solver slices default to 4 s; a solver that is
   still producing candidates near its slice end gets one extension up to 2× if
   the global deadline has room. Deterministic work (key-space enumeration) uses
   fixed iteration budgets, so results do not change when the machine is busy.
   After a verified exact recovery the search drains at most 8 more nodes and
   stops spawning new expansions — deterministic, load-independent output.

### Common commands (cheat-sheet)

```
autocrypt                            # open the interactive UI (no file args, TTY)
autocrypt --help                    # full CLI reference
autocrypt --update                  # self-update to the latest source
autocrypt message.txt               # solve a single blob/file
autocrypt -j1 message.txt           # run single-threaded (deterministic ordering)
autocrypt --top 5 message.txt       # show only the top 5 ranked candidates
autocrypt --timeout 60 input.txt    # give it a 60s global budget
autocrypt --json input.txt          # machine-readable output (for scripting)
autocrypt --explain input.txt       # plain-English explanation under each result
autocrypt --fast input.txt          # ~half the time (skip slow brute-force)
autocrypt --deep input.txt          # 2x time + deeper layered decode search
autocrypt challenge.py output.txt   # solve a CTF challenge (.py + captured output)
```

For development from a source checkout (no install needed):

```
python -m autocrypt.cli             # interactive UI (same as bare `autocrypt`)
python -m autocrypt.cli message.txt # run the CLI directly from the repo root
bash run_tests.sh                   # run the regression table (43 cases)
python3 tests/test_matrix.py --both # exhaustive matrix checks
```

> **Interactive UI.** With no file arguments and a terminal attached (a TTY),
> a bare `autocrypt` launches an interactive session: paste or type the data
> you want analyzed, and pick from the ranked recovery chains it finds. When
> pasting ciphertext you can also supply an optional cipher key (blank = auto-
> crack); the key is passed to the decoders (e.g. Vigenère) and can be seen or
> cleared under **Settings → Cipher key**. For RSA, the **Enter RSA
> parameters** mode asks for `n`/`e`/`c` (required) and optional `p`/`q`/`d`
> (auto-detecting hex); supplying `d` decrypts directly. This is the same
> `autocrypt` command as everything above — just omit the file.

### Installation

Build an installable global `autocrypt` command on **Windows** or
**Linux/macOS**. Requires **Python ≥ 3.12** (stdlib only — no third-party
runtime dependencies).

Prerequisites:

- Python 3.12+ (`python --version`). On Windows, prefer the official Python
  installer — not the Microsoft Store alias (the installer detects and skips
  those stubs).
- Git (the installer runs `pip install -e .`; `autocrypt --update` uses git).

**Quick install — one-liner.** The fastest path downloads the installer
directly from GitHub and runs it. It clones the latest source into
`~/.autocrypt/src`, then does exactly what the local steps below do.

Linux / macOS (bash):

```bash
curl -fsSL https://raw.githubusercontent.com/marcogamer46/autocrypt/main/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/marcogamer46/autocrypt/main/install.ps1 | iex
```

Then open a **new** terminal and run `autocrypt --help`.

> Review what you run. Piping a remote script straight into your shell or
> PowerShell executes whatever is at that URL — a common but trust-sensitive
> pattern. To inspect first, fetch the script to a file, read it, then execute
> it locally (the "from a clone" steps below do exactly that).

#### Windows (PowerShell)

```powershell
cd C:\path\to\autocrypt
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

What it does:

1. Locates a real Python (drops the "Run as alias" Store stubs).
2. Creates a dedicated virtualenv at `C:\Users\<you>\.autocrypt\venv`
   (override the location with `$env:AUTOCRYPT_HOME`).
3. Installs the package *editable* from this repo.
4. Writes `<venv>\autocrypt.json` recording the repo path (used by `--update`).
5. Adds `<venv>\Scripts` to your **User PATH** (persistent; new terminals pick
   it up). Idempotent — safe to re-run at any time.

Open a **new** terminal and verify:

```
autocrypt --help
autocrypt message.txt        # solves the bundled sample in the repo root
```

#### Linux / macOS (bash)

```bash
cd /path/to/autocrypt
bash install.sh
```

Same steps; the venv goes to `~/.autocrypt/venv`, and a guarded
`export PATH="...:$PATH"` line is appended to `~/.profile`, `~/.bashrc`
and/or `~/.zshrc` (only if not already present). Re-source a profile or open a
new shell, then:

```
autocrypt --help
```

#### Uninstall

Delete `~/.autocrypt` (`%USERPROFILE%\.autocrypt`), remove the PATH entries the
installer added, and optionally `pip uninstall autocrypt`. Both installers print
exact uninstall instructions when they finish.

### Self-update

An installed `autocrypt` can update itself at any time:

```
autocrypt --update     # long form
autocrypt -update      # single-dash alias
```

The one-liner installers (`curl … | bash` / `irm … | iex`) give you an install
that is fully self-updateable — you never need to re-run the installer to get
new fixes. Just run `autocrypt --update` whenever you want the latest build:

```
autocrypt --update     # pulls latest source + reinstalls (if needed)
autocrypt --version    # confirm the new version
autocrypt --help       # confirm the command still works
```

Behavior:

- The updater detects how the install was created: a git checkout (walks parent
  directories for `.git`), the installer-written `<venv>/autocrypt.json`, or a
  pip vcs/archive install.
- For a git checkout it runs `git fetch` + `git pull --ff-only` and reinstalls
  if the install is non-editable. It **refuses to run on a dirty working tree**
  (uncommitted changes) — commit or stash first.
- Only non-destructive commands are ever executed (`git fetch`,
  `git pull --ff-only`, `pip install --upgrade`).
- If the install was created some other way, it prints the correct manual
  command instead of guessing.

### Repository layout

```
autocrypt/            the importable package (cli, core, ui, scoring, solvers*,
                      challenge, filetypes, stego, lattice, czroots, explain,
                      watcher, updater, _version, __main__)
tools/                dev utilities (make_fixtures.py, e3_section.py, …)
tests/                regression suites (test_*.py)
fixtures/             deterministically generated fixtures (make_fixtures.py)
real_challenges/      real CTF challenges + honest benchmark (BENCHMARK.md)
docs/                 scoring & solver documentation
archive_scratch/      frozen dev scratch / tools_dev
install.sh, install.ps1   platform installers
pyproject.toml        packaging (console script: autocrypt = "autocrypt.cli:main")
```

From a source checkout *without* installing, the equivalent command is
`python -m autocrypt.cli <file> [options]` run in the repo root.

### Invocation

```
autocrypt <file>... [options]
```

`<file>` may be plain data (`.txt`, binary, image, …) and/or a challenge `.py`
generator. Multi-file input (`challenge.py output.txt`) is merged by static AST
parsing — challenge `.py` files are never executed, only read.

| Option | Meaning |
|---|---|
| `--top N` | show at most N ranked results (default 200) |
| `--timeout S` | global time budget in seconds (default 20) |
| `-j N, --jobs N` | worker processes (default `min(cpu_count,8)`; 1 = sequential) |
| `--json` | emit machine-readable JSON `{status, failures, first_exact, results}` |
| `--verbose` | explain each accept/reject and print per-solver timings |
| `--strict` | exit non-zero after finishing if any unexpected solver exception occurred (same as `AUTOCRYPT_STRICT=1`) |
| `--explain` | print a plain-English sentence under each ranked result |
| `--flag-format RE` | regex used for early/direct flag detection |
| `--wordlist WORDLIST` | wordlist for hash / JWT-secret cracking |
| `--known-plaintext CRIB` | known plaintext crib |
| `--params PARAMS` | RSA parameters, e.g. `n=...,e=...,c=...` (optional `p=...`,`q=...` or `d=...`) |
| `--fast` | ~half the time: shorter per-solver slices, skip the slowest brute-force solvers |
| `--deep` | 2× per-solver time + deeper layered decode search (max depth 6→9) |
| `--beam-width N` | max children expanded per search node (default 64; use a small N for speed, larger for stacked classical layers) |
| `--key KEY` | known cipher key (Vigenère keyword, or an ASCII/hex XOR key); blank = crack automatically |
| `--failures PATH` | append undecoded inputs as JSONL to PATH (default `failures.jsonl`); also read by `--replay` |
| `--replay` | rerun every logged failure and report which now decode |
| `--no-color` | disable ANSI colors |
| `--update` / `-update` | self-update (see above) |

Examples:

```
autocrypt message.txt
autocrypt --json --top 5 --explain challenge.py output.txt
autocrypt --timeout 60 --deep stubborn_input.txt
autocrypt --failures /tmp/failures.jsonl mystery.bin
autocrypt --replay --failures /tmp/failures.jsonl   # which failures now decode?
autocrypt --key lemon cipher.txt                       # decrypt with known key
autocrypt rsablocks.txt      # RSA: list of ciphertext values + n=/e= lines
```

When an input cannot be decoded, autocrypt appends one JSON line to
`failures.jsonl` (or the `--failures` path): raw input (base64), timestamp,
decoders tried, and best score reached. `--replay` reruns every logged failure
and reports which ones now pass — handy after adding new solvers.


## Real CTF challenges (`.py` + `output.txt`)

CTF crypto challenges usually ship a generator/encryption script plus captured
output. autocrypt ingests both in one invocation, e.g.:

```
autocrypt real_challenges/sumoprimes/gen.py real_challenges/sumoprimes/output.txt
```

The `.py` file is parsed statically (never executed): label-carrying `print()`
calls, assigned constants, and hex/`pow(g,…)` hints are extracted and merged
with the output so the solver can find `n/e/c`, primes, keys, or leaks that live
only in the source. Real curated challenges live under `real_challenges/` (see
`LOGS.md` Session 7/8/11 for what they exercised and fixed).

## How to add a solver

1. Write a function in a `solvers*.py` file decorated with
   `@solver(name, matches)`, where `matches(fp)` returns a prior probability in
   `[0,1]` given the fingerprint dict (charset, entropy, magic, …).
2. The function is a generator: `solve(data, ctx)` yields tuples
   `(plaintext, method, params, claimed_score)`. `plaintext` is `bytes` (or a
   ready-to-display string). Use `yield` for each candidate; the search stops
   when you stop yielding or your time slice ends.
3. If the solver recognizes labeled values (`n=`, `c=`, `key=`, …) use the
   `_vals(data, ctx)` / `_pick(...)` helpers instead of regexing raw text — they
   understand the labeled-line extraction from `challenge.py`.
4. Score honestly: `ctx.assess(pt)` gives English/flag evidence; a verified
   recovery (attack math checks out) may claim high confidence, a statistical
   guess should not. Set `_statistical` in params when the result is a guess.
5. Register the solver in the `test_*` family you extend and add a `run_tests.sh`
   row if it has a deterministic expected flag.

## Solver families

- Encodings: hex (+separator-tolerant), base16/32/64/64url/58/85, binary,
  octal, decimal bytes, morse, url, quoted-printable, bytes-literal, int-list,
  hexdump, radix-ascii, DNA, two-symbol, braille, base32hex, Crockford, Z85,
  custom alphabet, reverse words / reverse-each-word, PEM/JWT payloads, gzip/zlib.
- Classical ciphers: Caesar/ROT13/ROT47/ROT18, atbash, affine (all 312 keys,
  leet-body evidence), Vigenere-dictionary/wordlist, Beaufort, Porta,
  Gronsfeld, autokey-with-crib, Hill 3×3 (crib), monoalphabetic substitution,
  rail fence, scytale, columnar transposition, playfair, bifid, trifid,
  nihilist, four-square, straddling checkerboard, Enigma M3 (direct + crib).
- XOR: single-byte, repeating-key (key lengths 2–5 with flag-shape constrained
  joint enumeration, work-budgeted), many-time-pad, known-plaintext crib.
- Number theory / public-key: small-e exact root, Wiener, factored RSA (incl.
  p/q-labeled input), known-d / p/q direct decrypt, block RSA (per-value list
  sharing one n/e), shared-prime gcd, dp/dq leak, known p+q, even-e roots,
  multi-prime, Franklin-Reiter (m2 = a·m + b), common modulus, Hastad-style C
  (triple labels), Pollard p−1/p+1/rho/ECM factoring, DLP via Pohlig-Hellman
  for smooth groups, EC arithmetic + BSGS, ECDSA/DSA nonce reuse, LCG recovery,
  MT19937 prediction, hash cracking (md5/sha1/sha224/sha256/sha384/sha512/ntlm)
  with hash→XOR decryption pairing.
- Stego: LSB PNG and WAV planes.

## Tests (regression suites)

All `test_*.py` suites live in `tests/` and are run from the repo root. Use the
repo's own interpreter (`.venv/Scripts/python.exe` on Windows,
`.venv/bin/python` on POSIX) or any `python3` ≥ 3.12:

```
bash run_tests.sh                # 43-case table (strict mode on) + optional AES/Fernet SKIP rows
python3 tests/test_matrix.py --both     # 22/22 rows rank #1
python3 archive_scratch/tools_dev/fuzz.py  # 12 malformed/random/unicode cases, no crashes
python3 tests/test_flagshape.py         # flag-shape gates
python3 tests/test_multijob.py          # 38/38: identical top-3 at -j1 vs -j4
python3 tests/test_hexfamily.py <seed> --matrix | --grid d12|d34
python3 tests/test_xorfamily.py         # L≥4 short-flag repeating-XOR family (7/10 accepted; known ambiguity)
python3 tests/test_blind3.py / test_blind4.py   # blind sets (seen-data regressions)
python3 tests/test_e3.py                # E3 realistic CTF pairs (strict harness)
python3 tests/test_e4.py                # challenge.py print-label extraction (10/10)
python3 tests/test_explain.py           # --explain (7/7)
python3 tests/test_e7.py                # --fast / --deep flags (4/4)
python3 tests/test_rsapqfamily.py / test_rsaexactfamily.py / test_families_turn.py
python3 archive_scratch/tools_dev/flakecheck.py <seed> --grid d34 [--contend]  # idle vs loaded determinism
python3 archive_scratch/tools_dev/rsa_battery.py  # 11 raw RSA attack classes (baseline 10/11)
```

Standalone diagnostics / dev tools (fuzz, flakecheck, rsa_battery, diag, …)
live under `archive_scratch/tools_dev/` (and `tools/`) to keep the root clean.

All fixtures under `fixtures/` are generated deterministically by
`tools/make_fixtures.py` (fixed seeds). Challenge pairs use synthetic flags
marked as such; the flag is never shipped inside a pair (real challenges read
`flag.txt`).
Real, third-party CTF challenges — the honest benchmark — live under
`real_challenges/`, with per-challenge run results in
`real_challenges/BENCHMARK.md`.

## Known limits

- Modern authenticated encryption / large-RSA general factoring are out of scope.
- Generic semiprimes beyond ~192-bit (where the built-in p−1/p+1/rho/ECM are
  practical) are not factored; such inputs need an external QS/GNFS tool.
- 4–5-byte repeating-key XOR over ~20-char flags is inherently ambiguous;
  the family target is 7/10.
- Source-hint propagation (keys/shifts inside challenge `.py`) is a planned
  next step for the E3 set.
