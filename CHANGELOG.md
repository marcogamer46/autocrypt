# Changelog

All notable changes to AutoCrypt are recorded here. Format: version → notable
changes. See `PROGRESS.md` for detailed work logs and `LOGS.md` for the
chronological session record.

## 0.11.8 (unreleased) — fix Caesar flag-shaped recovery (full-wordlist body coherence)

- Fixes the `cracked Caesar` branch introduced in 0.11.7: that version referenced
  `_FLAGISH` without importing it, so the branch raised `NameError` and the whole
  Caesar solver silently contributed no candidates (leave as-is masking the result).
- The branch now scans all 25 shifts for one that reveals a flag-shaped output whose
  `{body}` tokens are *real dictionary words* (a fuller built-in English wordlist,
  not the small `_COMMON` set). This recovers encrypted bodies whose tokens fall
  outside `_COMMON` — e.g. `jzww{la_ab_iybal}` → `cspp{et_tu_brute}` (shift 7/19,
  "et tu, Brute"). Works for any encrypted prefix (no known-prefix gate). Conservative
  guards (fraction ≥ 0.75 and gain over input) keep random shifts from firing.
- Test: `tests/test_caesar_flagshape.py::test_caesar_nonenglish_latin_body_recovers`.
  Full suite green.

## 0.11.7 (unreleased) — Caesar flag-shaped recovery

- `solve_caesar` now scans all 25 shifts for one that reveals a recognized flag
  wrapper (`flag{…}`, `ctf{…}`, `picoCTF{…}`, `htb{…}`, `academy{…}`, …) whose
  leet/`-body plausibility *gains* over the input, and surfaces that as a
  confident `cracked Caesar` candidate (choosing the max-gain shift). CTF flag
  bodies are often leet/random-looking and therefore ranked mid-list by generic
  English scoring; the gained flag-shape evidence is decisive. Classic English
  Caesar recovery is unchanged.
- Tests: `tests/test_caesar_flagshape.py` (flag recovery across prefixes +
  English regression guard). Full suite green.

## 0.11.6 (unreleased) — morse punctuation/leniency + binary padded tokens + save fix

- **Morse**: added common punctuation to the table (`. , ? ' ! / ( ) & : ; = + - _ " $ @`);
  `|` is now accepted as a letter separator in place of space; unknown tokens are
  skipped instead of aborting the whole decode.
- **Binary**: space-separated tokens are left-padded to 8 bits each, so leading-zero
  stripped bytes recover (e.g. `1001000 1101001` → `Hi`) alongside the standard 8-bit
  stream; non `0/1` characters are ignored.
- **UI save fix**: `_save` now auto-creates missing parent directories (txt and json)
  instead of failing with "No such file or directory".
- Tests: `tests/test_morse_binary.py` (unit-level solver checks + live-UI integration);
  `tests/test_ui_safety.py::test_save_creates_parent_dirs`.

## 0.11.5 (unreleased) — RSA mode UX + block-RSA + d-only decryption

- **RSA mode** (was "Enter RSA parameters"): the menu entry is now
  `3. RSA mode (paste n,e,c)`, and pasting accepts multi-line / comma- /
  semicolon-separated labeled fields (`n=…`, `e=…`, `c=…`, optional `p=…`,
  `q=…`, `d=…`; `=` or `:` separators; case-insensitive keys with aliases like
  `modulus`/`exponent`/`ciphertext`/`priv`; hex auto-detected, incl. `0X`).
  Missing required fields are prompted for individually, and the parsed fields
  are echoed before solving. Empty input cancels cleanly back to the menu.
- **d-only decryption**: a supplied private exponent `d` now decrypts without
  needing `e` (`m = c^d mod n`); when `e` is present the result is verified via
  `pow(m, e, n) == c`, so a wrong `d` is never emitted as a confident result
  and never blocks the factoring/crack paths.
- **Block RSA**: a ciphertext that is a *list* of values all sharing `n`/`e`
  (e.g. one per plaintext byte) is now recovered — factor once, decrypt every
  block (`RSA block`). Known parameter values are excluded so supplied `p/q/d`
  are never misread as blocks.
- Unlabeled numeric fallback no longer misreads a labeled `n,c,d` triple as
  `n,e,c`; tiny-modulus guard relaxed (n < 32) so genuine tiny-RSA passes.
- Block-RSA detection excludes `p1..pN`/`q1..qN` source-hint primes (as well as
  `p/q/d`), so multi-prime challenges (e.g. `test_e4`) are never misread as a
  list of ciphertext blocks.
- Tests: `tests/test_rsa_ui_phase7.py` expanded to 14 checks (d-only, p/q
  path, multiline/uppercase parse, hex autodetect, missing-required, wrong-d
  safety, block-RSA, plaintext == pow(c,d,n)).

## 0.11.4 (unreleased) — Phase 7: RSA UI mode with optional private exponent

- **RSA UI mode** (`Enter RSA parameters`): accepts `n`/`e`/`c` (required) and
  optional `p`/`q`/`d` (private exponent), each auto-detecting hex (0x or
  `[a-f]` digits). The RSA solver now consumes a supplied `d` directly — it
  decrypts with `m = c^d mod n` without factoring or attacking (`RSA known-d`
  recovery), and the UI prints the recovered bytes as hex alongside the text.
- RSA label scan now also recognizes `d`/`priv`/`private_exponent` in pasted
  parameter text; `--params`/`--key` paths are unchanged.
- Tests: `tests/test_rsa_ui_phase7.py`.

## 0.11.3 (unreleased) — Phase 6: extras — UTF-16, bzip2, XOR user key

- **UTF-16 / UTF-32 text** decoder (`utf16-text`): auto-detects BOM and endian
  (LE/BE), recovers flags hidden in wide-character text.
- **bzip2 decompression**: the existing compression solver now also decodes
  bzip2 (`BZh…` magic), alongside gzip and zlib.
- **XOR with a user key**: the single-byte and repeating-key XOR solvers now
  honor `--key` (ASCII or hex bytes) — a supplied key decrypts immediately,
  while a blank key keeps the statistical crack. A wrong key never breaks the
  auto-crack path.
- No artificial throttling is present in solvers; per-solver work stays on the
  budget-aware scheduler.
- Tests: `tests/test_extras_phase6.py`.

## 0.11.2 (unreleased) — Phase 5: UI input modes (paste ciphertext + key)

- Interactive UI: pasting ciphertext now prompts for an optional cipher key
  (blank = auto-crack); the key is passed through to the decoders
  (`solve_data(key=...)`), and is visible/editable as a new Settings entry
  ("Cipher key"). A blank key keeps the automatic crack path.
- Tests: `tests/test_ui_phase5.py` (key forwarding, blank-key default, Settings
  store). No new CLI flags — the CLI already accepts `--key` (Phase 4).

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
