# Architecture

This page is a map of the autocrypt codebase: where the logic lives, how the solver
registry works, and what each directory holds. For the runtime flow, see
[how-it-works](how-it-works.md).

## Package layout (`autocrypt/`)

The package lives at `autocrypt/`. `__init__.py` is intentionally minimal: it only
re-exports the CLI entry points and registers the solvers. It must not import
`autocrypt.ui` eagerly, because `ui.py` imports the package back (which would cause a
circular-init crash).

| Module | What it does |
| --- | --- |
| `core.py` | The heart: `fingerprint()`, the solver `REGISTRY` and `@solver` decorator, the `Context` dataclass, the free-fixpoint pre-pass, and the bounded best-first `search()`. |
| `scoring.py` | English-likeness model (quadgrams, letter frequency, dictionary evidence), `assess()`, and flag-body plausibility helpers. |
| `cli.py` | Command-line entry point: argument parsing, `solve_data()` orchestration, output formatting, `--update` dispatch. |
| `__main__.py` | Lets `python -m autocrypt` run the CLI (imports `cli.main`). |
| `solvers*.py` | The registry payload: `solvers.py` plus `solvers_mega.py`, `solvers_more.py`, `solvers_pack3.py`, `solvers_pack5.py`, `solvers_pack6.py`, `solvers_pack7.py`, `solvers_extra.py`, `solvers_plus.py` — the 140+ cipher/encoding/math solvers. |
| `challenge.py` | Challenge-file support: statically reads a CTF source `.py` (never executes it) plus its output `.txt`, and labels unlabeled numbers into `name=value` inputs. |
| `stego.py` | Image/file steganography and binary-artifact solvers (LSB, appended archives, QR codes). Degrades gracefully if optional deps like Pillow/numpy/opencv are missing. |
| `lattice.py` | LLL basis reduction and Coppersmith's method, the machinery behind the RSA partial-p solver. Deterministic integer arithmetic. |
| `czroots.py` | Cantor-Zassenhaus root-finding for the integer polynomials produced by LLL-reduced Coppersmith vectors. |
| `explain.py` | Human-readable explanations of each recovery chain layer for `--explain`. |
| `watcher.py` | A Claude Code watchdog dev tool (restarts/wakes a `claude --continue` session) — not part of the solving pipeline. |
| `updater.py` | Self-update for `autocrypt --update`, dispatches on how the install was created (git checkout, installer venv, pip), refuses dirty trees, never runs destructive commands. |
| `filetypes.py` | Tiny dependency-free file-type sniffing shared by core and the stego solvers. |
| `_version.py` | Version string. |

## The solver registry pattern

New solvers are registered with a decorator:

```python
@solver("name", matches)
def solve(data, ctx):
    ...
```

The `solver` decorator appends a `Solver(name, matches, solve)` record to the global
`REGISTRY` in `core.py`.

- `matches` is a function `matches(fingerprint) -> float` returning a prior (0..1)
  saying how relevant this solver is to the input. Registers with a prior of 0 are
  skipped.
- `solve` is a generator `solve(data, ctx) -> yields` producing candidate plaintexts.
  Each yield carries the plaintext, a method name (e.g. `caesar(shift=7)`), optional
  parameters, and a claimed score. The search re-scores every yield through
  `scoring.assess()`.

Adding a solver means writing a match rule and a generator — nothing else needs to
change. Solvers can read `ctx` (deadline, wordlist, RSA params, known plaintext,
etc.) and must respect the global deadline.

## Entry points

- **Console script:** `autocrypt.cli:main` — the `autocrypt` command on PATH.
- **Module run:** `python -m autocrypt.cli <file> [options]` (or
  `python -m autocrypt`) from a clone without installing.
- **Interactive mode:** running `autocrypt` with no arguments and a TTY stdin drops
  into the interactive terminal UI in `ui.py`.
- **Self-update:** `autocrypt --update` (alias `-update`) pulls the latest code via
  git and reinstalls into the active venv; it refuses a dirty working tree.

## Top-level directories

| Directory | Contents |
| --- | --- |
| `tools/` | Dev utilities (not shipped): `gen.py`, `make_fixtures.py`, `tm.py` / `tm_e4.py` (experiments), `e3_section.py`, `scratch_watchdog.py`, `_download_train.py`. |
| `tests/` | `pytest` test modules covering solver families (affine, RSA, XOR, transposition, flag-shape heuristic, UI safety, multi-job, etc.). |
| `fixtures/` | Small sample inputs for many cipher/encoding types (base64, DNA, braille, DLP, RSA samples, LSB stego images, WAV, etc.) used by tests. |
| `real_challenges/` | Real CTF challenge data (RSA, rail-fence, substitution, etc.) and `BENCHMARK.md`, an honest benchmark of solver performance. |
| `docs/` | `SOLVERS.md` (the full solver catalog), `SCORING.md` (the scoring model), and this `wiki/`. |

## Further reading

- [`docs/SOLVERS.md`](../SOLVERS.md) — the solver catalog.
- [`docs/SCORING.md`](../SCORING.md) — the scoring model.
- [`real_challenges/BENCHMARK.md`](../../real_challenges/BENCHMARK.md) — honest benchmark.
- [how-it-works](how-it-works.md) — the runtime pipeline.
