# Testing

autocrypt has three layers of verification: the **regression table** (`run_tests.sh`), the **standalone suites** (`tests/test_*.py`), and the **honest real-challenge benchmark** (`real_challenges/BENCHMARK.md`). All fixtures are generated deterministically so results are reproducible.

## The regression table: `run_tests.sh`

Run from the repo root with your shell's bash:

```bash
bash run_tests.sh
```

What it does:

- Sets `AUTOCRYPT_STRICT=1`, so any unexpected (bug-class) solver exception **fails the suite** instead of being silently swallowed.
- Picks the interpreter: `.venv/Scripts/python.exe` on Windows, else `python3`.
- Regenerates `fixtures/` on demand via `tools/make_fixtures.py` if it is missing or incomplete.
- Runs a **43-case table**. Each case invokes `python -m autocrypt.cli <file> [args]` under a `timeout 25` and greps the output for an **exact expected flag** — only deterministic, exact recoveries are asserted. Cases cover encodings, classical ciphers, XOR, RSA/DLP attacks, LCG/MT19937, stego, and real challenge pairs.
- Finishes with the **optional-library tests** (`tests/test_optional.py`), which print `SKIP` when a library is absent; a non-SKIP failure still fails the suite.
- Prints `TOTAL=… PASS=… FAIL=…`.

## Running any test standalone

Every `tests/test_*.py` is a self-contained script with a `main()` that exits `0` on success. Run it directly with the repo's own interpreter (the tests set `PYTHONPATH` to the repo root themselves):

```bash
# Windows
.venv/Scripts/python.exe tests/test_rot13_academy.py
# POSIX
python3 tests/test_rot13_academy.py
```

Representative suites:

```bash
python3 tests/test_matrix.py --both                 # 22/22 rows rank #1
python3 tests/test_multijob.py                      # 38/38: identical top-3 at -j1 vs -j4
python3 tests/test_flagshape.py                     # flag-shape gates
python3 tests/test_e3.py                            # E3 realistic CTF pairs (strict harness)
python3 tests/test_e4.py                            # challenge.py print-label extraction (10/10)
python3 tests/test_explain.py                       # --explain (7/7)
python3 tests/test_e7.py                            # --fast / --deep flags (4/4)
python3 tests/test_hexfamily.py <seed> --matrix     # hex family matrix
python3 tests/test_xorfamily.py                     # repeating-XOR family
python3 tests/test_blind3.py / test_blind4.py       # blind sets (seen-data regressions)
```

If you add a solver, add a suite in this style covering its deterministic expected output.

## Generating fixtures: `tools/make_fixtures.py`

All files under `fixtures/` are created by one deterministic script:

```bash
python3 tools/make_fixtures.py
```

- It uses a **fixed seed** (`random.seed(20261101)`), so regenerating produces **byte-identical fixtures** — required for the regression tests to stay stable.
- It writes to `fixtures/` and prints one `wrote …` line per file.
- It also builds the E3 realistic CTF challenge pairs via `tools/e3_section.py`.
- Challenge fixtures use **synthetic flags** marked as such; the flag is never shipped inside a pair (real challenges read `flag.txt`).

`run_tests.sh` calls this automatically when `fixtures/` is missing, so you rarely need to run it by hand.

## The honest benchmark: `real_challenges/BENCHMARK.md`

The benchmark at `real_challenges/BENCHMARK.md` compares autocrypt against **RsaCtfTool** and **Ciphey** on **real, held-out CTF challenges** (PicoCTF 2021/2022/2023, CSAW Red 2020) that the autocrypt author did not write. It is deliberately honest:

- Every tool's run is a documented CLI invocation with a real timeout; a "FAIL" is a timeout or junk output, not a crash.
- **RsaCtfTool** is installed from git into `.venv_bench/` (its PyPI package does not exist); **Ciphey could not be installed** on Python 3.12 (its `cipheycore` wheel is capped at CPython 3.9), so its column is truthfully `N/A` — no results are fabricated.
- Per-challenge rows record which tool solved, failed, or was not applicable, with notes on how (e.g. FactorDB dependence, a known J/Q substitution ambiguity).
- The narrative is candid about wins (small-e RSA, substitution), losses (rail-fence, Sum-O-Primes), and where the comparison is incomplete. Read it before claiming the tool is a general CTF solver.

## Related pages

- [Adding a new solver](adding-a-solver.md) — what to test when you extend the registry.
- [Solver families](solvers.md) and [how results are scored](scoring.md) — context for what the suites assert.
- Benchmark: [BENCHMARK.md](../../real_challenges/BENCHMARK.md).
