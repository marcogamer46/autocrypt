# Command-line reference

`autocrypt` is a command-line tool that fingerprints unknown data and searches for common CTF crypto weaknesses. This page is the full reference for its command-line interface, generated from `autocrypt/cli.py`.

## Running it

There are two ways to invoke the CLI:

| Invocation | When to use |
|---|---|
| `autocrypt <file> [options]` | Installed version (via `install.sh` / `install.ps1`). Puts `autocrypt` on PATH. |
| `python -m autocrypt.cli <file> [options]` | Running straight from a clone without installing. |

Both behave identically; only the entry point differs. If you run with no arguments and stdin is a terminal, autocrypt drops into its interactive UI instead of the batch CLI.

## Positional argument

| Argument | Meaning | Default |
|---|---|---|
| `file` | One or more input paths: data `.txt` files and/or a challenge `.py` (read for static analysis, never executed). Use `-` for stdin. | `-` (stdin) |

You can pass a data file and a challenge `.py` together so the solver can use static hints from the challenge source.

## Options

| Option | Meaning | Default |
|---|---|---|
| `--flag-format <regex>` | Regex used for early flag detection. | `\w{1,40}\{.*?\}` |
| `--top <n>` | Maximum number of text results to report (must be non-negative). | `200` |
| `--timeout <sec>` | Global time budget in seconds (must be positive). | `20.0` |
| `-j`, `--jobs <n>` | Number of worker processes. `1` = sequential. | `min(cpu_count, 8)` |
| `--json` | Emit results as JSON (all fields) with `status` / `failures`. | off |
| `--explain` | Print a plain-English explanation of each recovery chain layer. | off |
| `--verbose` | Explain why each candidate was accepted or rejected. | off |
| `--strict` | Fail (non-zero exit, after finishing) on unexpected solver exceptions. | off |
| `--wordlist <path>` | Wordlist file for hash and JWT-secret cracking. | (none) |
| `--known-plaintext <crib>` | Known plaintext crib. | `""` |
| `--params <spec>` | RSA parameters, e.g. `"n=...,e=...,c=..."`. | `""` |
| `--fast` | Cut time in half: shorter per-solver slices, skip the slowest brute-force solvers. | off |
| `--deep` | 2x per-solver time and a deeper search (for stubborn challenges). | off |
| `--no-color` | Disable terminal colors. | off |
| `--update`, `-update` | Self-update: pull latest code from the git repo this install was made from and reinstall into the active virtualenv. | off |

### Notes on the flags

- **RSA params** parse `key=value` pairs separated by commas, semicolons, or whitespace. Values with a `0x` prefix are read as hex. This is the hook for feeding known RSA parameters when they aren't embedded in the challenge.
- **`--fast` vs `--deep`** are opposites. `--fast` runs half-length per-solver slices and skips the heavy brute-force solvers (`dlp-composite-smooth`, `hill-2x2`, `enigma-m3`, `hash-crack`, `vigenere-brute`). `--deep` doubles per-solver time and raises the search depth limit from 6 to 9.
- **`--strict`** also activates when the environment variable `AUTOCRYPT_STRICT` is set. When strict mode fails, the exit code is non-zero.
- **`--update`** refuses to touch a dirty git working tree and never runs destructive commands; it delegates to the updater module.

## Output

A normal run prints a fingerprint header (length, entropy, charset, index of coincidence, magic/tells, hash-like fingerprint, encoding hypotheses), then challenge/finding notes, then ranked results. Each result row is numbered and shows:

- the decode **chain** (e.g. `base64 → XOR-single-byte → flag`),
- a confidence score plus a reason label (`*** FLAG ***` for flags, `LOW CONFIDENCE` for short samples),
- the recovered plaintext.

With `--json`, the output is a single JSON object with `status`, `failures`, `first_exact`, and `results` (each result has `chain`, `plaintext`, `confidence`, `is_flag`, `_reason`).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `2` | Input error (e.g. unreadable file, invalid `--flag-format` regex, negative `--top` or non-positive `--timeout`). |
| `3` | Strict mode failed (after finishing). |

## Examples

```bash
# Solve a single data file (installed binary)
autocrypt challenge.txt

# Solve straight from a clone, without installing
python -m autocrypt.cli challenge.txt

# Combine a data file with the challenge source for static analysis
python -m autocrypt.cli data.txt challenge.py

# JSON output, limited to the top 50 results
autocrypt --json --top 50 data.bin

# Feed a wordlist and a crib for hash / JWT cracking
autocrypt --wordlist words.txt --known-plaintext "FLAG{" file.bin

# More time and deeper search for a stubborn challenge
autocrypt --timeout 60 --deep stubborn_file

# Provide RSA parameters explicitly
autocrypt --params "n=...,e=...,c=..." rsa.txt

# Read input from stdin
cat file.bin | autocrypt

# Self-update
autocrypt --update
```

## Related pages

- [How results are scored](scoring.md) — what confidence and rank mean.
- [Solver families](solvers.md) — what the search can detect.
- Full catalog: [SOLVERS.md](../SOLVERS.md), full scoring model: [SCORING.md](../SCORING.md).
