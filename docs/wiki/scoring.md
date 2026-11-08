# How results are scored

Every ranked row in autocrypt's output answers "why does this candidate win?" with a single score. This page summarizes the evidence model behind that score. The detailed, authoritative write-up lives in [SCORING.md](../SCORING.md).

## Three separate questions

autocrypt never asks one "is this English?" question. Instead it asks three separate questions and combines the answers:

1. **Is the raw text human-readable?** — `scoring.plain_text_score` uses character-level statistics over a built-in unigram table. Any non-printable byte earns `-inf`. A bonus is granted for the generic `prefix{body}` flag shape, which is why flag bodies rank high even when they contain digits/underscores that pure English quadgrams would punish.
2. **Does it look like English?** — `scoring.assess` blends three statistical features, choosing weights by sample length.
3. **Does it look like a real flag?** — `scoring.flag_plausibility` maps leetspeak bodies back to letters (`0`→`o`, `3`→`e`, `4`→`a`, `5`→`s`, `7`→`t`, `@`→`a`, `$`→`s`) and runs the quadgram model on the *body* only. This ranks `academy{c4n_y0u_cr4ck}` above `academy{x9q1z7}` without ever deciding unilaterally that something is flag-shaped.

## The English score in detail

`assess()` is a weighted blend of four features:

| Feature | Short text (<60 letters) | Long text | Source |
|---|---|---|---|
| Quadgram score `q` | 10% | 66% | English quadgram log-probability table; sums per-window log-probs |
| Letter-frequency chi-square | 35% | 18% | Standard English letter frequencies; transformed via `exp(-2·χ²/N)` |
| Common-word hit ratio | 49% | 10% | Corpus top-4000 words plus a curated CTF/flag vocabulary |
| Printability | 6% | 6% | Fraction of printable characters |

Two guards prevent overconfidence:

- `has_partial_english()` caps any result at **0.60** when the text contains recognizable English words alongside unrecognizable ones (a partial solve).
- Under 20 letters the reason string explicitly says `LOW CONFIDENCE` because statistical features overfit tiny samples.

The readability thresholds: `≥0.82` strong, `≥0.62` English-like, `≥0.40` inconclusive, below that is weak/false-positive risk.

## How a solver's claim interacts with the rank

Every solver yields `(plaintext, method, params, claimed_score)`. The final rank is not just `claimed_score`:

- **Verified exact recoveries** (RSA attack math checks out, a crib decodes deterministically, an encoding round-trips) get a **trust tier** that keeps them above speculative statistics.
- **Statistical guesses** (e.g. Hill-2×2, dictionary substitution) set `_statistical` in their params, capping their trust relative to verified rows.
- Both the **flag-plausibility** body score and the **English** `assess()` score are consulted by the ranker; a candidate that satisfies both is preferred.

## Determinism

Scoring is **deterministic and load-independent**:

- No randomness is used in the scoring path.
- Time-bounded search uses fixed iteration budgets for key-space enumeration.
- The search drains at most 8 extra nodes after a verified exact recovery and stops spawning new expansions, so output does not change when the machine is busy.

## Reading a result row

Each row shows the decode **chain** (e.g. `base64 → XOR-single-byte → flag`), the recovered **plaintext**, a **method** string, and a **score/confidence**. The `--explain` flag prints a plain-English sentence per layer describing what was done (e.g. `base64 decoded (length 48)`, `single-byte XOR key 0xa7`).

## What it is not

This is a heuristic plaintext model, not a proof of Englishness. It is tuned for short CTF flag bodies, so a deliberately random but flag-shaped string can score highly — that is by design. It is *not* used to hide failures: if nothing clears the threshold, the tool reports the status honestly.

## Related pages

- [Command-line reference](cli.md) — how to read scores in the output.
- [Solver families](solvers.md) — the candidates being scored.
- Full model: [SCORING.md](../SCORING.md).
