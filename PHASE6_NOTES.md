# Phase 6 — General smart mode (design notes)

Working spec captured before implementation. **Do not start Phase 6 until the
Phase 1/2/3 missing fixes are committed (see PROGRESS.md).**

## Goal
A new mode (one menu entry) that:
- holds a transform library with type signatures,
- labels the structure of intermediate states (structure labels) and tracks progress,
- detects unknown cipher families from statistics (unknown-cipher detection),
- forms key hypotheses,
- spends a GPU by nodes/iterations, not wall-clock — so `-j1/-j4` give identical
  results, and
- learns from solves (`solved_chains.jsonl`).

## Benchmark generator (`gen_chains.py`)
- TRAIN / HOLDOUT, 500 each, fixed seeds.
- Reports solve rate by depth / step / plaintext-type.
- Must not regress `run_tests.sh`, `test_matrix.py`, `fuzz.py`.

## User-supplied constraints (applies to implementation)
- **Pruning is the weak point, not the library.** The wider the library, the
  bigger the search space; structure labels + cipher-family detection (B and C)
  are what prune. Without them a large transform library just makes the search
  slower and noisier. That is why the benchmark reports solve rate *by depth*:
  if depth 4–6 collapses, pruning is the weak point.
- **Holdout must stay fair.** Keep the HOLDOUT seed secret from the agent / out
  of the agent's context. Generate the holdout file once, run it only at the
  end, and never print individual failures. Otherwise we would fix the holdout
  cases one by one and it stops being a fair test.
- Revert overfitting: if a change improves TRAIN but degrades HOLDOUT, it stays out.
