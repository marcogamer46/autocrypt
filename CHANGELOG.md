# Changelog

All notable changes to AutoCrypt are recorded here. Format: version → notable
changes. See `PROGRESS.md` for detailed work logs and `LOGS.md` for the
chronological session record.

## 0.11.1 (unreleased) — Phase 3: layered beam search; Phase 4: Vigenère + user key

- **Layered beam search** (`--beam-width`, default 64): per-node child-width
  cap, a cheap-transforms pass (reverse / swap-case / strip-whitespace, kept
  only when it reveals a flag or gains English), and shared visited-string
  de-dup across all expansions. Profiling counters (`nodes_expanded`,
  `children_pushed`, `transforms_run`, `per_depth`) are surfaced in
  `--verbose` and JSON `search_stats`. Note: the roadmap's "width 3" default
  prunes deep classical stacking (vig→affine→caesar), so the default is 64.
- **Vigenère user key** (`--key`): pass a known cipher key to decrypt Vigenère
  directly (`vigenere(key)` recovery) instead of only cracking statistically;
  blank keeps the Kasiski/IoC + per-column Caesar auto-crack.
- Tests: `tests/test_beam.py`, `tests/test_vigenere_crack.py`.

## 0.11.0 (unreleased) — Phase 2: unified scoring

- New `autocrypt.scoring.score()`: one 0..1 plaintext-likeness score blending
  English confidence (quadgram + dictionary), letter-frequency chi-square,
  index of coincidence, dictionary density, and printable ratio — plus a large
  flag bonus. The bonus is quality-scaled for the default `flag{...}` shape
  (up to +0.45 × body plausibility, so random-letter flag shells don't float)
  and flat +0.5 for an explicit user-supplied `flag_regex` (authoritative).
- New `autocrypt.scoring.index_of_coincidence()` (Friedman IoC).
- `assess()` (used by the whole search pipeline) now includes the index-of-
  coincidence term, improving English-vs-scrambled discrimination.
- Tests: `tests/test_scoring.py`.

## 0.10.9 (unreleased) — Phase 1: failure log + replay

- **Failure log**: when an input cannot be decoded, the CLI appends one JSON
  line to `failures.jsonl` (raw input base64-encoded, timestamp, decoders
  tried, best score reached, plus the replay-affecting parameters). Path
  overridable with `--failures PATH`; disabled under
  `AUTOCRYPT_NO_FAILURES_LOG=1` (used by the test harness).
- **`--replay`**: reruns every logged failure through the normal pipeline and
  reports which now pass — useful after adding new solvers.
- New module `autocrypt/failures.py`; `solve_data()` gained
  `failure_log_path`. Tests: `tests/test_failures.py`.

## 0.10.8 — xor5_w2 fix

- Repeating-key XOR solver: flag-aware structural objective
  (`_flag_evidence`) + per-brace-position shape enumeration so true short
  flags (L≥4, n≤60) surface. `test_xorfamily.py` back to 10/10.

## 0.10.7 — audit bug-fix batch 2 (#36–48)

- base100 (leading-zero stripping, radix-100 subset), Ook (double-punct
  tokens), Brainfuck (step-budget truncation), JWT (HS256 header confusion),
  java.random (state predecessor), registry dedup + gaps-wins, EC int parsing,
  challenge label regex, harness timeout-hang (rc=124) handling.

## 0.10.6 — audit bug-fix pass (#1–34)

- Root-cause fixes across solvers/framework from the 49-item audited list;
  34 bug fixes.

## 0.10.5 — gap-filling solvers batch 3

- Brainfuck/Ook interpreters, MT19937 clone.

## 0.10.4 — gap-filling solvers batch 2

- base100 decode, MD5/SHA-1 length extension, hardened JWT key-confusion.

## 0.10.3 — gap-filling solvers batch 1

- PowerShell EncodedCommand, Unicode-tag stego, Java Random recovery,
  JWT RS256→HS256 confusion.

## 0.10.0 — UI banner, version tag, changelog

- Real version tag surfaced in the UI banner; update changelog display.

## 0.9.0 — budget-aware scheduling

- Budget-aware scheduling, partial progress reporting, stacked classical
  layers.

## 0.3.0 / 0.2.0 — solver packs

- 0.3.0: symmetric known-key solver pack.
- 0.2.0: LFSR fields solver; installer/updater fixes.
