# autocrypt

A CLI CTF crypto auto-solver. Given an unknown blob (or a challenge `.py` +
captured output), it fingerprints the data and runs a best-first layered decode
search over a registry of classical ciphers, encodings, and exact math attacks,
then ranks the surviving plaintext candidates.

Built and tested for Python 3.12+ (stdlib only; optional crypto libs are never
required and never executed).

## Design overview

### Pipeline

```
input -> fingerprint(data) -> best-first layered decode search (core.py)
         -> solver registry (solvers*.py)
         -> candidate records (chain, plaintext, confidence, trust)
         -> rank + display (autocrypt.py / ui.py)
```

1. **Fingerprint** (`core.fingerprint`): cheap structural stats — charset,
   length, entropy, index of coincidence, magic bytes, and regex-based encoding
   classes (hex, base64/base32, binary, octal, …). The `prior_map` drives which
   solvers get scheduled.
2. **Best-first search** (`core.search`): a priority heap of decode nodes.
   Each node is a byte blob plus a chain of transforms that produced it.
   Priorities combine the chain prior, fingerprint prior, and the score of the
   decode that created the node. Deep decoder chains get a gentle depth boost so
   they are not starved by shallow guesses.
3. **Free fixpoint pre-pass** (`core._free_fixpoint`): unambiguous whole-buffer
   decodings (hex/base64/base32/binary, including separator-tolerant hex) are
   stripped for free before the graph search, so pure encoding stacks do not
   consume node budget.
4. **Solver registry** (`@solver(name, matches)` decorator): each solver
   declares a `matches(fp)` prior and a generator `solve(data, ctx)` that yields
   `(plaintext, method, params, claimed_score)`. New solvers are added by
   writing one function + prior.
5. **Scoring/ranking** (`scoring.py`, `core.py`): per-candidate evidence =
   English quadgrams + dictionary-word fraction, leet-body dictionary fraction
   for flag-shaped outputs, and consistency checks for fixed substitutions.
   Rows carry a trust tier; verified exact recoveries (RSA attacks, crib-based
   crackings, direct decodes) are kept above speculative statistics.
6. **Time/load robustness**: per-solver slices default to 4 s; a solver that is
   still producing candidates near its slice end gets one extension up to 2× if
   the global deadline has room. Deterministic work (key-space enumeration) uses
   fixed iteration budgets, so results do not change when the machine is busy.
   After a verified exact recovery the search drains at most 8 more nodes and
   stops spawning new expansions — deterministic, load-independent output.

### Invocation

```
python3 autocrypt.py <file> [--json] [--verbose] [--top N] [--timeout S]
                     [--jobs N] [--strict] [--flag-format RE]
                     [--explain] [--fast] [--deep]
```

- Multi-file input (`challenge.py output.txt`) is merged by static AST parsing —
  challenge `.py` files are never executed.
- `--json` emits `{status, failures, first_exact, results}`.
- `--verbose` explains accept/reject and prints per-solver timings.
- `--strict` (or `AUTOCRYPT_STRICT=1`): any unexpected solver exception
  (NameError, TypeError, …) makes the run exit non-zero after finishing.
- `--explain` prints a plain-English sentence under each ranked result explaining
  how each chain layer was decoded/broken.
- `--fast` cuts time roughly in half (shorter per-solver slices) and skips the
  most expensive brute-force solvers (DLP smoothing, Hill-2×2, Enigma, hash
  cracking, Vigenère brute). Use when you want a quick answer.
- `--deep` doubles per-solver time and allows a deeper layered decode search
  (max depth 6 → 9) for stubborn multi-layer challenges.

## Real CTF challenges (`.py` + `output.txt`)

CTF crypto challenges usually ship a generator/encryption script plus captured
output. autocrypt ingests both in one invocation, e.g.:

```
python3 autocrypt.py real_challenges/sumoprimes/gen.py real_challenges/sumoprimes/output.txt
```

The `.py` file is parsed statically (never executed): label-carrying `print()`
calls, assigned constants, and hex/`pow(g,…)` hints are extracted and merged
with the output so the solver can find `n/e/c`, primes, keys, or leaks that live
only in the source. Real curated challenges live under `real_challenges/` (see
`LOGS.md` Session 7/8/11 for what they exercised and fixed).

## How to add a solver

1. Write a function in a `solvers*.py` file decorated with
   `@solver(name, matches)`, where `matches(fp)` returns a prior probability in
   `[0,1]` given the fingerprint dict (charset, entropy, magic, …).
2. The function is a generator: `solve(data, ctx)` yields tuples
   `(plaintext, method, params, claimed_score)`. `plaintext` is `bytes` (or a
   ready-to-display string). Use `yield` for each candidate; the search stops
   when you stop yielding or your time slice ends.
3. If the solver recognizes labeled values (`n=`, `c=`, `key=`, …) use the
   `_vals(data, ctx)` / `_pick(...)` helpers instead of regexing raw text — they
   understand the labeled-line extraction from `challenge.py`.
4. Score honestly: `ctx.assess(pt)` gives English/flag evidence; a verified
   recovery (attack math checks out) may claim high confidence, a statistical
   guess should not. Set `_statistical` in params when the result is a guess.
5. Register the solver in the `test_*` family you extend and add a `run_tests.sh`
   row if it has a deterministic expected flag.

## Solver families

- Encodings: hex (+separator-tolerant), base16/32/64/64url/58/85, binary,
  octal, decimal bytes, morse, url, quoted-printable, bytes-literal, int-list,
  hexdump, radix-ascii, DNA, two-symbol, braille, base32hex, Crockford, Z85,
  custom alphabet, reverse words / reverse-each-word, PEM/JWT payloads, gzip/zlib.
- Classical ciphers: Caesar/ROT13/ROT47/ROT18, atbash, affine (all 312 keys,
  leet-body evidence), Vigenere-dictionary/wordlist, Beaufort, Porta,
  Gronsfeld, autokey-with-crib, Hill 3×3 (crib), monoalphabetic substitution,
  rail fence, scytale, columnar transposition, playfair, bifid, trifid,
  nihilist, four-square, straddling checkerboard, Enigma M3 (direct + crib).
- XOR: single-byte, repeating-key (key lengths 2–5 with flag-shape constrained
  joint enumeration, work-budgeted), many-time-pad, known-plaintext crib.
- Number theory / public-key: small-e exact root, Wiener, factored RSA (incl.
  p/q-labeled input), shared-prime gcd, dp/dq leak, known p+q, even-e roots,
  multi-prime, Franklin-Reiter (m2 = a·m + b), common modulus, Hastad-style C
  (triple labels), Pollard p−1/p+1/rho/ECM factoring, DLP via Pohlig-Hellman
  for smooth groups, EC arithmetic + BSGS, ECDSA/DSA nonce reuse, LCG recovery,
  MT19937 prediction, hash cracking (md5/sha1/sha224/sha256/sha384/sha512/ntlm)
  with hash→XOR decryption pairing.
- Stego: LSB PNG and WAV planes.

## Tests (regression suites)

```
bash run_tests.sh          # 40-case table (strict mode on), plus optional AES/Fernet SKIP rows
python3 test_matrix.py --both     # 22/22 rows rank #1
python3 fuzz.py                   # 12 malformed/random/unicode cases, no crashes
python3 test_flagshape.py         # flag-shape gates
python3 test_multijob.py          # 38/38: identical top-3 at -j1 vs -j4
python3 test_hexfamily.py <seed> --matrix | --grid d12|d34
python3 test_xorfamily.py         # L≥4 short-flag repeating-XOR family (7/10 accepted; known ambiguity)
python3 test_blind3.py / test_blind4.py   # blind sets (seen-data regressions)
python3 test_e3.py                # E3 realistic CTF pairs (strict harness)
python3 test_e4.py                # challenge.py print-label extraction (10/10)
python3 test_explain.py           # --explain (7/7)
python3 test_e7.py                # --fast / --deep flags (4/4)
python3 test_rsapqfamily.py / test_rsaexactfamily.py / test_families_turn.py
python3 flakecheck.py <seed> --grid d34 [--contend]   # idle vs loaded determinism
```

All fixtures under `fixtures/` are generated deterministically by
`make_fixtures.py` (fixed seeds). Challenge pairs use synthetic flags marked as
such; the flag is never shipped inside a pair (real challenges read `flag.txt`).

## Known limits

- Modern authenticated encryption / large-RSA general factoring are out of scope.
- 4–5-byte repeating-key XOR over ~20-char flags is inherently ambiguous;
  the family target is 7/10.
- Source-hint propagation (keys/shifts inside challenge `.py`) is a planned
  next step for the E3 set.
