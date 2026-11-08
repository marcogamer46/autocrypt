# Autocrypt Wiki

Welcome to the autocrypt wiki. This is the friendliest place to start if you
want to understand what autocrypt does, why it exists, and how to use it.

## What is autocrypt?

Autocrypt is a **CLI CTF crypto auto-solver**. You hand it an unknown blob of
data (or a CTF challenge script plus its captured output), and it tries to
figure out what cipher or encoding hides the flag, recover the plaintext, and
rank the candidate solutions. It ships with a registry of 146 solvers covering
classical ciphers, encodings, XOR, and number-theory / RSA attacks.

It is built for **Python 3.12+** using only the standard library — there are no
third-party runtime dependencies to install.

## Who is this for?

- **CTF players** who want a fast second opinion on a crypto challenge.
- **Learners** who want to see how a modern auto-solver is built.
- **Contributors** who want to understand the architecture and add solvers.

## Table of contents

### Start here

| Page | What it covers |
|---|---|
| [Overview](overview.md) | What autocrypt does and why it exists, in plain non-technical language. |
| [Quickstart](quickstart.md) | The fastest path from zero to a solved file: install, first command, and output. |

### How it works

| Page | What it covers |
|---|---|
| [SOLVERS.md](../SOLVERS.md) | The full catalog of all 146 registered solvers, the module map, and how priorities are set. |
| [SCORING.md](../SCORING.md) | How candidate plaintexts are scored and ranked (English evidence, flag-plausibility, trust tiers). |

### Reference

| Page | What it covers |
|---|---|
| [README.md](../../README.md) | The main project readme: design overview, full CLI reference, solver families, and tests. |
| [BENCHMARK.md](../../real_challenges/BENCHMARK.md) | An honest, reproducible benchmark of autocrypt vs RsaCtfTool and Ciphey on real CTF challenges. |

### Developing

| Page | What it covers |
|---|---|
| [LOGS.md](../../LOGS.md) | The chronological work log of sessions and steps. |
| [PROGRESS.md](../../PROGRESS.md) | The current status mirror of the work log. |
| [README.md](../../README.md) | Includes a "How to add a solver" guide in the "Developing" section. |

## Project layout at a glance

- `autocrypt/` — the importable package (`cli`, `core`, `ui`, `scoring`,
  `solvers*.py`, `challenge`, `filetypes`, `stego`, `lattice`, `czroots`,
  `explain`, `watcher`, `updater`, `_version`, `__main__`).
- `tools/` — dev utilities.
- `tests/` — regression suites.
- `fixtures/` — deterministically generated fixtures.
- `real_challenges/` — real CTF challenges and the honest benchmark.

For an installation-free way to run from a source checkout:
`python -m autocrypt.cli <file> [options]` in the repo root.
