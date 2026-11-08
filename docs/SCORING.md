# How autocrypt scores results

This document explains the evidence model that decides which candidate plaintexts
are shown and in what order. It is the honest answer to "why does this solver
win?" — every ranked row in the output is the product of the pipeline below.

## Three distinct questions

autocrypt never asks a single "is this English?" question. It asks three
separate questions and combines the answers:

1. **Is the raw text human-readable?** (`scoring.plain_text_score`)
   Character-level statistics over a unigram table built from a built-in corpus.
   Anything with a non-printable byte gets `-inf`. A bonus is granted for the
   generic `prefix{body}` flag shape, which is why flag bodies rank high even
   when they contain digits/underscores that pure English quadgrams would punish.
2. **Does it look like English?** (`scoring.assess`)
   A weighted combination of three statistical features, choosing weights by
   sample length.
3. **Does it look like a real flag?** (`scoring.flag_plausibility`)
   A separate, flag-specific ranking that maps leetspeak bodies back to letters
   (`0`→`o`, `3`→`e`, `4`→`a`, `5`→`s`, `7`→`t`, `@`→`a`, `$`→`s`)
   and then runs the quadgram model on the *body* only. This ranks
   `academy{c4n_y0u_cr4ck}` above `academy{x9q1z7}` without ever deciding
   unilaterally that something is flag-shaped.

## `assess()` in detail

The English score is a weighted blend of:

| Feature | Small text (<60 letters) | Long text | Source |
|---|---|---|---|
| Quadgram score `q` | 10% | 66% | `_build_table()` — a `dict` of English quadgram log-probabilities built from a large bundled corpus; `quadgram_score()` walks the text and sums per-window log-probs |
| Letter-frequency chi-square | 35% | 18% | `_LETTER_FREQ` (standard English letter frequencies); chi-square statistic transformed via `exp(-2·χ²/N)` |
| Common-word hit ratio | 49% | 10% | `_COMMON` — a word list merged from the corpus top-4000 and a curated CTF/flag vocabulary (so `flag`, `ctf`, `leet`, `pwn`, `vibe` count as "known words") |
| Printability | 6% | 6% | fraction of printable characters |

Two guards prevent overconfidence:

- `has_partial_english()` caps any result at **0.60** when the text contains
  recognizable English words but also unrecognizable ones (a partial solve).
- Under 20 letters the reason string explicitly says `LOW CONFIDENCE` because
  statistical features overfit tiny samples.

The human-readable threshold tiers: `≥0.82` strong, `≥0.62` English-like,
`≥0.40` inconclusive, below — weak/false-positive risk.

## How a solver's claim interacts with the rank

Every solver yields `(plaintext, method, params, claimed_score)`. The final
rank is not just `claimed_score`:

- **Verified exact recoveries** (RSA attack math checks out, a crib decodes
  deterministically, an encoding round-trips) are given a **trust tier** that
  keeps them above speculative statistics. See `core.py` for the trust-tagging.
- **Statistical guesses** (e.g. Hill-2×2, dictionary substitution) must set
  `_statistical` in their params, which caps their trust relative to verified
  rows.
- The **flag-plausibility** body score and the **English** `assess()` score are
  both consulted by the ranker; a candidate that satisfies both is preferred.

## Determinism

Scoring is **deterministic and load-independent**:

- No randomness is used in the scoring path.
- Time-bounded search uses fixed iteration budgets for key-space enumeration.
- The search drains at most 8 extra nodes after a verified exact recovery and
  stops spawning new expansions, so output does not change when the machine is
  busy.

## Reading a result row

Each row shows the decode **chain** (e.g. `base64 → XOR-single-byte → flag`),
the recovered **plaintext**, a **method** string, and a **score/confidence**.
The `--explain` flag prints a plain-English sentence per layer describing what
was done (e.g. "base64 decoded (length 48)", "single-byte XOR key 0xa7").

## What it is not

This is a heuristic plaintext model, not a proof of Englishness. It is tuned for
short CTF flag bodies, so a deliberately random but flag-shaped string can score
highly — that is by design (the flag-shape signal is the point). It is *not*
used to hide failures: if nothing clears the threshold, the tool reports
`status: failed` honestly.
