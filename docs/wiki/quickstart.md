# Quickstart

This page gets you from zero to a solved file as fast as possible.

## Prerequisites

- **Python 3.12+** (`python --version`). On Windows, prefer the official Python
  installer — not the Microsoft Store alias.
- **Git** (the installer runs `pip install -e .`, and `autocrypt --update`
  uses git).

## Install

The fastest path downloads the installer directly from GitHub and runs it. It
clones the latest source into `~/.autocrypt/src` and puts `autocrypt` on your
PATH.

**Linux / macOS** (in a terminal):

```bash
curl -fsSL https://raw.githubusercontent.com/marcogamer46/autocrypt/main/install.sh | bash
```

**Windows** (in PowerShell):

```powershell
irm https://raw.githubusercontent.com/marcogamer46/autocrypt/main/install.ps1 | iex
```

> Review what you run. Piping a remote script straight into your shell executes
> whatever is at that URL — a common but trust-sensitive pattern. To inspect
> first, fetch the script to a file, read it, then run it locally.

Then open a **new** terminal and verify:

```
autocrypt --help
```

### Installing from a local clone

If you already have the repository checked out:

- Windows: `powershell -ExecutionPolicy Bypass -File .\install.ps1`
- Linux/macOS: `bash install.sh`

Both create a dedicated virtualenv (at `~/.autocrypt/venv`), install the
package editable, and add it to your PATH. If you'd rather not install at all,
you can run from the source checkout with `python -m autocrypt.cli <file> [options]`.

### Self-update

```
autocrypt --update     # long form
autocrypt -update      # single-dash alias
```

This pulls the latest code via git. It refuses to run on a dirty working tree
(uncommitted changes) — commit or stash first.

## First command

The repo ships a bundled sample flag `message.txt` at the root. Try:

```
autocrypt message.txt
```

If you have a real CTF challenge that ships a generator script plus captured
output, point autocrypt at both in one invocation:

```
autocrypt challenge.py output.txt
```

The `.py` file is parsed statically (never executed), so labels, constants, and
hints from the source are merged with the output.

## What the output means

Autocrypt prints a ranked list of candidate solutions. Each result row shows:

- **The chain** — the sequence of transforms that led to it, for example
  `base64 → XOR-single-byte → flag`.
- **The recovered plaintext** — the candidate answer.
- **A method** — which solver decoded it.
- **A score / confidence** — how strong the evidence is.

If nothing clears the quality bar, the tool reports `status: failed` honestly.

## Common flags

| Flag | What it does |
|---|---|
| `--top N` | Show at most N ranked results (default 200). |
| `--timeout S` | Global time budget in seconds (default 20). |
| `--jobs N` / `-j N` | Worker processes (default `min(cpu_count,8)`). |
| `--json` | Emit machine-readable JSON: `{status, failures, first_exact, results}`. |
| `--explain` | Print a plain-English sentence under each ranked result. |
| `--verbose` | Explain each accept/reject and print per-solver timings. |
| `--fast` | About half the time: shorter per-solver slices, skip the slowest brute-force solvers. |
| `--deep` | 2x per-solver time plus a deeper layered decode search. |
| `--strict` | Exit non-zero if any unexpected solver exception occurred. |

Some examples:

```
autocrypt --json --top 5 --explain challenge.py output.txt
autocrypt --timeout 60 --deep stubborn_input.txt
```

### A note on `--explain`

The `--explain` flag turns the terse chain notation into sentences, e.g.
`"base64 decoded (length 48)"` or `"single-byte XOR key 0xa7"`. It is the
quickest way to understand *why* a result ranked the way it did.

## Next steps

- Understand the approach at a high level: [Overview](overview.md).
- Dive into the scoring model: [SCORING.md](../SCORING.md).
- Browse every solver: [SOLVERS.md](../SOLVERS.md).
- See how autocrypt fares against other tools on real challenges:
  [BENCHMARK.md](../../real_challenges/BENCHMARK.md).
