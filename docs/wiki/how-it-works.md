# How It Works

autocrypt is a pipelin drive that turns an unknown blob into a short, ranked list of
candidate plaintexts — with any convincing `FLAG` results called out. The whole
pipeline lives in [`autocrypt/core.py`](../../autocrypt/core.py) and leans on
[`autocrypt/scoring.py`](../../autocrypt/scoring.py) to decide what "looks right".

The high-level flow is:

```
fingerprint -> best-first layered decode search -> solver registry -> scoring/ranking
```

Here is each stage in plain terms.

## 1. Fingerprint

Before solving anything, `fingerprint()` computes *cheap structural statistics* about the
input. It never tries to decode — it just measures what the data looks like:

- length, **entropy** (bits/byte), **character set** (empty / binary / ascii-text / mixed),
  printable fraction, and **index of coincidence** (IC),
- rough encoding guesses pulled from the shape of the bytes: hex, base64, base32,
  binary, octal, decimal, morse, URL-encoding, JWT, PEM, and more — each with a
  prior probability,
- **magic bytes** (gzip, zlib, PEM) and **hash-likeness** (MD5, SHA-1, SHA-256,
  bcrypt …),
- a file-type sniff via `autocrypt.filetypes`.

The fingerprint is deliberately separate from solving: it is cheap, and it is what
decides which solvers are worth trying on this input.

## 2. The free fixpoint pre-pass

Before applying any cipher, `_free_fixpoint()` peels off unambiguous encoding layers
for free. If the whole buffer strictly parses as hex, base64, base32, or binary — and
the decoded output is itself a plausible next encoding layer — it decodes without
spending any depth or time-slice budget.

Because the decoder alphabets overlap (any binary string is also valid hex, and any
base32 string is also valid base64), it prefers the *strictest* match: a pure `0/1`
buffer decodes as binary, not junk hex, and an uppercase base32 blob is not swallowed
by the base64 branch. The result is an unwrapped payload (and the chain of layer names)
that the real solvers then attack.

## 3. The solver registry

`core.py` keeps a global `REGISTRY` of solvers. Each solver is registered with the
`@solver(name, matches)` decorator and provides two things:

- a **match rule** (`matches(fingerprint) -> prior probability`) that says how likely
  this solver is relevant to the input, and
- a **solve generator** (`solve(data, context) -> candidates`) that yields possible
  plaintexts.

Only solvers whose match prior is positive and who survive the fingerprint gates get
run; they are scheduled best-first by prior. The catalog lives in
[`docs/SOLVERS.md`](../SOLVERS.md) — there are over 140 of them.

## 4. Best-first layered decode search

The engine is a **best-first search over a heap of states**, where each node is a blob
plus the chain of transforms that produced it.

- The heap is keyed by priority (roughly the product of the prior and the running
  chain probability), with a monotonically increasing serial number to keep ties
  deterministic.
- A `visited` set of SHA-256 digests stops the same state from being explored twice.
- Search is bounded three ways: by **depth** (default 6, 9 under `--deep`), by a
  **global deadline** (the `--timeout`, default 20 s), and by the visited-hash set.
- When a candidate is itself another encoding (fingerprints with magic bytes or a
  high-prior encoding class), it is **expanded** and pushed back onto the heap, so
  layered chains like `base64 -> hex -> caesar` are discovered automatically. Classical
  (non-encoding) chains are not combinatorially piled up — only a fingerprint-encoding
  output may continue.

### Parallelism

When `--jobs > 1` and the input is large enough, solvers are distributed across a
`ProcessPoolExecutor`. Each worker runs one solver to completion or its deadline; the
main loop then waits for that solver's results within the remaining global budget.

## 5. Time and load robustness

Two properties keep runs predictable:

- **Per-solver slices.** Each solver gets roughly a **4-second slice** of the global
  budget (scaled by `--fast` = 0.5x and `--deep` = 2x). This stops one slow solver
  from eating the whole timeout. A few named solvers (RSA, composite-DLP) get larger
  fixed slices because their work is deterministic but can exceed 4 s. Heavy
  brute-force solvers are skipped entirely under `--fast`.
- **Adaptive extension.** If a solver is *still producing valid candidates* near the
  end of its slice and the global deadline has room, the slice is extended once by up
  to 2x — so deterministic enumeration work is not cut short just because the machine
  is momentarily busy.

The search is **deterministic**: time-bounded, with fixed budgets and deterministic
solvers (e.g. the LLL lattice work is documented as deterministic), so the same input
with the same flags gives the same ranked output.

## 6. Scoring and ranking

Every candidate is scored by `assess()` in `scoring.py`, which combines a **quadgram**
English model, letter-frequency (chi-square) fit, and dictionary-word evidence. Scores
are 0..1; short samples weight real word evidence more heavily because their
statistics are unreliable. Flags get their own plausibility treatment (see below).

Results are then **ranked**. The sort key prefers, in order: verified English over
flags for the top slot, then confidence, then an internal "trust" level, then how much
of a flag body is real (leet-aware) dictionary text, then the chain. Low-confidence
junk is filtered out before display unless it is a flag or a verified exact recovery.

## 7. How a candidate becomes a `FLAG`

A candidate is marked `is_flag` only when it clears a strict evidence gate:

1. It matches the flag regex (default `\w{1,40}\{.*?\}`, overridable with
   `--flag-format`).
2. It starts with a **known CTF prefix** (`flag{`, `ctf{`, `picoctf{`, …) or was
   recovered by a verified exact attack, **and** its body is plausible
   (`flag_plausibility`), which is leet-aware — so `WH3R3_D035` counts.
3. The flag-shaped match covers essentially the whole buffer, the output is printable
   ASCII (no replacement chars), and it is **not** just an echo of the input.
4. For classical transforms on an already-flag-shaped input, a consistency check
   (`_consistent_flag_recovery`) confirms the claimed transform really reproduces the
   candidate — junk "decodes" that merely restyle the body are demoted, not trusted.

A confirmed flag is assigned confidence at least 0.95 and the search stops immediately,
returning status `FOUND`. Flag-shaped candidates that fail one of these gates are still
ranked (below the as-is floor) so the search can keep looking for the real decode.

## Search status

The final `SearchResult` carries a status: `FOUND`, `TIMEOUT`, `SOLVER_FAILED`,
`TOO_SHORT`, or `NOT_FOUND`. The CLI prints this, the ranked candidates, and (with
`--explain`) a plain-English explanation of each recovery chain, built by
`autocrypt/explain.py`.

## Further reading

- [`docs/SOLVERS.md`](../SOLVERS.md) — the full solver catalog.
- [`docs/SCORING.md`](../SCORING.md) — the scoring model in detail.
- [`real_challenges/BENCHMARK.md`](../../real_challenges/BENCHMARK.md) — an honest
  benchmark against real CTF challenges.
