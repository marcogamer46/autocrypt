# autocrypt progress

## where we are (2026-11-08, ultracode continuation) — COMPLETE

User request (this round): "organize files into folders; install script for
Windows and Linux so `autocrypt` works on any terminal; `autocrypt -update`
self-update; update README (curl/irm one-liners, wiki, how to update,
commands)".

Done:
- **Package layout**: the ~20 flat runtime modules moved into `autocrypt/`
  (git mv + import rewrites); dev tools moved to `tools/`; added
  `autocrypt/__init__.py`, `_version.py` (0.1.0), `__main__.py` (`python -m
  autocrypt`), `updater.py`. `pyproject.toml` now uses `packages=["autocrypt"]`,
  dynamic version from `autocrypt._version.__version__`, console script
  `autocrypt = "autocrypt.cli:main"`.
- **Updater** `autocrypt/updater.py`: dispatches on how the install was made
  (git checkout via parent-walk `.git` detection, installer venv config at
  `<venv>/autocrypt.json`, or pip vcs/editable install); refuses dirty git
  trees; only non-destructive commands (`git fetch`/`git pull --ff-only`,
  `pip install --upgrade`). Wired into the CLI as `--update` (alias `-update`).
- **Installers**: `install.sh` (Linux/macOS) and `install.ps1` (Windows) create
  `~/.autocrypt/venv`, `pip install -e .`, persist PATH (guarded rc lines /
  user env var), write `<venv>/autocrypt.json` recording the repo path for
  `--update`. Idempotent; safe to re-run.
- **Tests**: all `tests/` migrated to package-qualified imports and
  `[sys.executable, "-m", "autocrypt.cli", ...]` with `cwd=str(ROOT)`.
- **Wiki**: 11-page beginner-friendly hub under `docs/wiki/` (index, overview,
  quickstart, how-it-works, architecture, cli, scoring, solvers,
  adding-a-solver, testing, faq). All links verified to resolve.
- **README**: one-liner installers (`curl -fsSL … | bash` / `irm … | iex`),
  Windows/Linux install steps, self-update section, common-commands
  cheat-sheet, full CLI options table, repo layout, tests section.
- **Substitution-wordlist regression fixed**: `_load_sub_dict()` was looking for
  `english_words.txt` inside the package dir after the restructure (wordlist is
  at repo root) → now resolves package dir / repo root / CWD.
- **Adversarial review fixes** (ultracode workflow): fixed 7 confirmed findings
  in the updater (mis-dispatch, exit codes, Windows file:// path), installers
  (swallowed pull failures, unescaped JSON, Python version gate), and added a
  real `--version` CLI flag (see LOGS S38.11).
- **Final baseline**: `run_tests.sh` **43/43 PASS**; standalone suite 33/34
  (only `test_flaws2` = BKLG-22, 18 pre-existing p−1/p+1 flaws — not a
  regression). Substitution-wordlist regression test passes.
- **Pushed**: commit `a5f186b` on `origin/main`. One-liner installer URLs live
  (HTTP 200): `raw.githubusercontent.com/marcogamer46/autocrypt/main/install.sh`
  and `install.ps1`, plus `README.md`.
- **Session 39 (installer "command not found" fix)**: diagnosed as *no real
  Python ≥3.12 on the machine* (only Microsoft Store alias stubs); completed
  the install via the `AUTOCRYPT_PYTHON` override so `autocrypt` works. Both
  installers now validate Python **before** cloning (fail-fast with a clear
  error instead of a silent half-install). See LOGS Session 39.

## Previous note (reviewer-feedback round) — COMPLETE

Reviewer-feedback round (structure + honest benchmark) is done. Repo
restructure: all 34 `test_*.py` moved into `tests/` (git mv + path-bootstrap
rewrites), standalone dev/diag tools moved to `archive_scratch/tools_dev/`,
added LICENSE (MIT), `pyproject.toml`, `docs/SCORING.md`, `docs/SOLVERS.md`
(146-solver catalog), and updated `run_tests.sh` + README paths. Verified
`run_tests.sh` 43/43 PASS and the moved `tests/` suite green.
Honest benchmark (`real_challenges/BENCHMARK.md`): autocrypt vs RsaCtfTool
(git-installed) vs Ciphey (N/A — cipheycore wheel capped at CPython 3.9).
New real challenges added: substitution0/1/2, rail-fence (picoCTF 2023/2022).
autocrypt wins small-e RSA (incl. Mini_RSA's c+i·n twist RsaCtfTool misses)
and all three monoalphabetic substitutions; loses on rail-fence and
Sum-O-Primes (p+q leak unused); Very_Smooth p−1 README claim did not reproduce
(report it as a backlog verification item, BKLG-21).

Backlog now: BKLG-18 (fill Ciphey gap on Python ≤3.9), BKLG-19 (rail-fence
miss), BKLG-20 (Sum-O-Primes not consuming x=p+q), BKLG-21 (verify/correct
Very_Smooth p−1 claim). See AUTO_MODE.md.

## Done
- R1-R6 (real online CTF challenges, 2026-11-05): curated 3 real picoCTF crypto challenges (miniRSA single-file e=3, Many Prime multi-file 4-prime RSA, rotation single-file ROT) into `real_challenges/`. Found and fixed 3 real bugs: (1) challenge.py hint extraction dropped multi-prime primes (p1..p4) so RSA tried to factor 372-bit composites — now emits `pN=`/`qN=` hints; (2) `solve_rsa_extra` given-primes short-circuit fell through to factor_all and burned the deadline (added `return`), and main `solve_rsa` (prior 0.99, runs first) starved the search by factoring under a 30s extension — ported the given-primes fast path into `solve_rsa` and extended `_rsa_values` regex to capture `p\d*|q\d*`; (3) labeled-line extraction didn't accept `0x` hex output, silently dropping n/c in multi-file hex challenges — now handles optional `0x`, New `test_rsamultiprimefamily.py` (10 cases, single-file + multi-file, decimal/hex) 10/10 rank #1 <0.5s; real multiprime pair added to `fixtures/multiprime_real/` + run_tests row. run_tests 41/41.
- B1 core.py: atbash on flag-shaped input ranks top (floor .95). atbash_flag_shaped.txt regenerated.
- B2 core.py: permuting methods allowed as recoveries when clearly more plausible AND flag spans >=75% of buffer (floor .98); rail-fence flag #1.
- B3 autocrypt.py: hide every non-flag result <0.60 unless exact recovery; flags always stay.
- B4 solvers_more.py: Williams p+1 (`_pp1`, Lucas fast-doubling) wired into factor_all between p-1 and rho; 3-safe-prime modulus recovered.
- B5 solvers_pack5.py: Trifid solver (9 alphabets x periods, decisive winner boosted). Recovers classic & period-5.
- B6 solvers_pack5.py: Nihilist solver (9 squares x phrases x conventions; crib-driven invert `Cracked nihilist`).
- B7 solvers_pack6.py: Four-square solver (6 keyword-pair hypotheses).
- B8 solvers_pack6.py: Gronsfeld (per-column unigram digit keys, lengths 1..20).
- B9 solvers_pack6.py: straddling checkerboard (two layouts).
- B10 solvers_pack6.py: Z85 decoder; custom-alphabet base decoder (`alphabet=`/`data=`).
- B11 solvers_pack6.py: EC arithmetic + BSGS + Pohlig-Hellman DLP; ECDSA nonce reuse.
- B12 solvers_pack6.py: Merkle-Hellman knapsack (MITM + superincreasing greedy).
- B13 stego.py: LSB brute force over all 8 bit planes x channel combos; Pillow-only fallback.
- B14 solvers_pack6.py: Enigma M3 (rotors I-V, reflectors B/C, plugboard, double-stepping); direct + crib brute-force.
- C1 core.py: decoder outputs with unknown flag prefix rank (floor .95) instead of exiting; t.txt chain recovered. TTFCTFGGH{...} variants pass.
- C2 solvers_pack7.py (new): bytes-literal / int-list / hexdump parsers.
- C3 pack7: CRT solver (>=8 moduli) + radix-ascii (bases 2..36).
- C4 pack7: reverse-words / reverse-each-word; 4-layer tests recover.
- C5 pack7: DSA nonce reuse (q,r,s1,s2,h1,h2).
- C6 pack7: RSA shared-prime gcd + dp/dq-leak CRT-RSA.
- C7 verified known p+q and e=4 even-e roots recoveries.
- C8 pack7: Franklin-Reiter incl. unlabeled `c1 c2 diff N` order.
- C9 pack7: LCG recovery (unknown modulus) + MT19937 prediction (>=624 outputs).
- C10 pack7: DH discrete log via Pohlig-Hellman over smooth p-1.
- C11 pack7: RC4 key (native); AES modes + Fernet wrappers (optional libs); ECB repeated-block finding.
- C12 pack7: hash cracking (md5/sha1/sha224/sha256/sha384/sha512/ntlm MD4) with wordlist/builtin/digits/lowercase+digits<=4, salted.
- C13 pack7: Vigenere-dictionary, Beaufort, Porta, autokey-with-crib, Hill 3x3 from 9-letter crib.
- C14 pack7: DNA, two-symbol, Braille, base32hex, Crockford, swapped-case base64, ROL/ROR/add/sub (skip printable).
- C15 stego.py: WAV LSB solver (all planes).
- C16 autocrypt.py: `--json` all fields+status+failures; `--verbose` accept/reject.
- C17 run_tests.sh: 32-case table (PASS/FAIL/seconds), 32/32 PASS.
- C18 fuzz.py: 12 malformed/random/unicode cases, no crashes, within time bounds.
- C19 core.py: per-solver 4s share; hill-2x2 expired() checks; known-prefix early exit.
- C20 README.md: grouped technique list + CLI examples.
- D1 scoring.py: new `english_confidence(text)` (quadgram + dictionary-word fraction). core.py: non-flag candidates with ec < 0.35 are capped at 0.55 (below display floor); final ranking tie-breaks by ec. Classical solvers boost only their most-English candidate with a continuous score 0.55+0.35·ec; vigenere-dict same; Hill3 scans all block phases/crib windows and only yields crib-matching success first. Verified: 6 English sentences x 6 ciphers (Beaufort, Porta, Hill 3x3, Gronsfeld, Trifid, Vigenere) -> correct plaintext is #1 in all 36/36 cases.

- D2 - test_matrix.py re-created (attached file) with only --json parsing adapted. Ran both F and E modes.
  Fixed to rank #1: plain, hex, base64, base64x2, caesar7, atbash, rot13, rot47, xor1 (hex/raw), binary, reverse, E railfence3, E xor1, E xorN.
  Core changes: as-is flag floor -> .96; non-exact flag rows clamped <= .97; forward-consistency validator for caesar/ROT/atbash/affine/vigenere/gronsfeld/beaufort/porta; tie-break - (confidence, ec, subst-ok, plaus delta, chain); atbash authoritative only when plaus improves; added xor-short joint solver (letter-frequency per position).
  Still not rank-1 (documented): F railfence3 — root causes: equal-confidence tie degeneracy among unknown-prefix flag transformations and missing whitespace/case reconstruction for English decodes.
- D3-fix (regressions from D1/D2 ranking changes, before D3): removed leftover debug prints that corrupted `--json` stdout (E caesar5, E vigenere, E base64 were failing only because of them). Added `clear_english()` (quadgram + real dictionary-word evidence; printable-ASCII gate; only tokens >=3 chars count) and gated the `_english_ok` sort key on it, so letter-only statistical junk (ec ~0.65 but zero dictionary words) no longer outranks confident flag/as-is decodes. The 0.86->0.97 consistency bump is now restricted to trusted, bounded key spaces (fixed substitutions, caesar shifts, dictionary/vigenere keys); statistically-derived keys (beaufort/porta/gronsfeld/affine/autokey) stay below the 0.96 as-is floor. Transposition strong-recovery additionally requires an English-confidence gain. Monoalphabetic substitution solver runs seeds (1,7,13,19) and boosts its most-English result exactly like other classical solvers (0.55+0.35·ec), so a converged English plaintext survives the keep floor. Verified: F vigenere(lemon), E caesar5, E substitution, E base64 all rank #1; full matrix = all rank 1 except documented xorN/rail-fence; run_tests.sh 32/32.
- D3 (short multi-byte XOR flags): `solve_xor_repeating` rewritten with a joint flag-aware objective: full key-space enumeration for L<=3 (shape-survivor union + score-capped candidates guarantees the true byte is evaluated; bigger cap for n>100), seed list = greedy + every `_flag_crib_xor` key + deterministic restarts, all under `_flagaware` (plain_text_score + flat flag-shape bonus + leet-body dictionary fraction with 1/3 digit variants + body alnum purity). `_repeat_xor_prior` now allows random-printable ciphertext (low IC) while excluding text-like blobs (IC>=0.055) and encoded blobs (base64/hex/...) so the layered decode chain (e.g. c1_layers) is not starved. Enriched `WORDS` with common CTF/leet vocabulary. Verified: F xorN(k3y) now rank #1 in the matrix; 19/20 random 3-byte-key flags recovered rank #1 (the 1 miss has a non-dictionary `zq7x` body — inherently ambiguous); run_tests.sh 32/32; matrix all rank 1 except documented rail-fence flag.
- D6 (rail-fence flag #1): the transposition strong-recovery gate no longer requires an `english_confidence` gain (transpositions preserve the letter multiset, so ec never changes). Instead a rail recovery is strong iff it starts at index 0, covers >=90% of the buffer, and its leet-body dictionary fraction increases over the input (`leet_body_dict_fraction` in scoring.py: leet-aware word matching with 1/3 variants, tokens >=3). `solve_rail` ranks flag-shaped inputs by that dictionary evidence first and yields up to 8 candidates (was 3, dropping the genuine rail). Strong recovery scores are proportional to the dict gain and are exempt from the 0.97 clamp. Braille table extended to full printable ASCII (space + 94 glyphs) so braces/underscores round-trip. Verified: F railfence3 and E railfence3 rank #1; 10/11 random rail tests (rails 2..6) rank #1 (1 miss is the non-dictionary `zq7x` body); run_tests.sh 32/32; fuzz.py ALL OK; matrix ALL rank 1 (no remaining failures).
- D4 (AES/Fernet tests with SKIP rows): new `test_optional.py` — builds a real AES-ECB case (pycryptodome) and a Fernet case (cryptography), runs them through `autocrypt.py`, and prints `aes_key` / `fernet_key` rows with PASS/FAIL/SKIP. When a library is missing the row is SKIP (not a failure); a FAIL with the library present fails the suite. `run_tests.sh` now runs this optional phase after the main 32-case table; the main summary stays TOTAL=32 PASS=32. Verified: with libs absent both rows SKIP, suite exit 0; run_tests.sh still 32/32; fuzz OK; matrix unaffected (all rank 1).
- D5 (Pollard rho speedup + optional ECM): `_rho` now batches 512 iterations per gcd (was 128) — fewer gcd calls per run; modular squaring remains the dominant cost, so the win is modest on pure-Python. Added a pure-Python Lenstra ECM stage-1 (`_ecm`, affine arithmetic, batched factor discovery via failed inverses) as the final fallback in `factor_all` after p-1/p+1/rho; guards limit it to n in [96,300] bits (small factors only — larger factors need B1/curve counts beyond a per-solver budget). ECM formulas verified against `_ec_mul` on a 127-bit prime field; a planted 40-bit factor is recovered in ~11s at B1=200k. The existing sympy ECM hook remains the preferred full-featured path when sympy is installed. Verified: run_tests.sh 32/32 (+ optional SKIP rows), fuzz ALL OK, matrix ALL rank 1.
- E1 (repo-owned fixtures): new `make_fixtures.py` regenerates all 30 fixtures into `fixtures/` deterministically (fixed seed 20261101; per-caller seeded RNGs). `run_tests.sh` now uses `$PWD/fixtures` and auto-runs `make_fixtures.py` when key files are missing; no more `/tmp` paths in test code (test_optional.py writes into fixtures/ too). Verified: fresh generation → 30 files; run_tests.sh 32/32 (+ optional SKIP rows).
- E2 (blind test set): new `test_blind.py` — 25 fresh cases with blind seed 20261231 (different from dev seeds), covering caesar, rot13, atbash, vigenere, xor (1-4-byte keys), base64/hex layers (1-4 deep), rail fence (2-5), RSA small cases (e=3 exact root and factored small modulus). First run was 64% → investigated and fixed real bugs (not the test): statistical flag-like margin rows capped to 0.95; full-buffer leet-body dictionary gain (`strong_evidence`) is now the evidence gate and trust tier (2) above fixed-only substitutions (1), with body dictionary fraction as the final tie-break; vigenere-dictionary accepts short flags (prior ≥12 bytes, ≥6 letters, top-5 candidates); `_factor` gained an `factor_all`/ECM fallback so small RSA factors; repeating-XOR enumeration covers L≤4 (n≤32) and L≤3 (n≤200) with a cheap pre-rank (plain_text_score) then full flag-aware scoring on the top 300 combos; `bytes-literal` added to decoder_names and deep decode nodes get a depth priority boost; exact full-buffer decoder rows get trust 2 so they beat key guesses at equal confidence. Final: 24/25 (96%) — threshold OK; the single unresolved case is a 3-byte-XOR-over-hex whose joint enumeration sits at the runtime slice edge (~3.9s vs 4s), an inherent time-budget flake, not a scoring bug. run_tests.sh remains 32/32.
- E2b (blind seed check): `test_blind2.py` = identical generator, blind seed 20270215. Result: 21/25 (84%) — below 90%. Failures (case names): `atbash`, `vigenere`, `hex4`, `rail5`. Real-bug fixes per failure (third-seed final check after all four).
- E2b-fix1 (atbash): root cause — a false-positive `RSA Franklin-Reiter` row (accidental small `c1/c2/diff/N` labels decrypt to m=3, control bytes) was labeled `recovered` (trust 3, conf 0.98) and outranked the true atbash decode. Fix: exact-attack rows whose output is not ≥90% printable are demoted below the display floor and stripped of recovered trust (`recovered_bad`); also discovered a latent debug-print NameError (`text` referenced before assignment) that was silently aborting recovered records (e.g. message DH) — removed. Family check: 10 fresh atbash flags (seed 20270301) → 10/10. run_tests.sh 32/32.
- E2b-fix2 (vigenere): root cause — `vigenere-dictionary` decrypted letters-only and returned an uppercase letter-only string, so even the correct key could never match the original flag (digits/braces/case dropped), and the true key ranked beyond the top-5 yielded candidates. Fix: weave decrypted letters back into the original text (preserving non-letters and case) and yield up to 12 dictionary candidates. Family check: 10 fresh vigenere flags (seed 20270302, random keys) → 10/10. run_tests.sh 32/32.
- E2b-fix3 (rail5): root cause — a `beaufort → base64 → repeating-key XOR` junk candidate with one accidental 3-letter dictionary token (`str`) passed `clear_english` (1/3 ≥ 0.30), got `_english_ok=True`, and sorted above the true 0.98 rail recovery. Fix: `clear_english` now requires dictionary_fraction ≥ 0.45 (single-word flukes no longer qualify). Also hardened Franklin-Reiter: solver refuses N < 128 bits or c1/c2 ≥ N (verified 0 false positives on text containing `c1`, `c2`, `n`). Family check: 10 fresh rail flags (seed 20270303, rails 2–6) → 10/10. run_tests.sh 32/32.
- E2b-fix4 (hex4 + tie regressions): root cause — junk rows starting with an accidental known prefix (e.g. `pwn{`) triggered the known-prefix early exit and returned a single junk result, discarding all real recoveries (this also broke vigenere(lemon), message DH, and hex4). Fix: known-prefix/full recovered flags now require a full-buffer flag shape (`len(match_text) ≥ 0.9·nonws`); recovered rows additionally need a flag shape/English/short technical verdict (`k=7`) to keep trust 3, and demoted non-solid recovered rows are capped at 0.55. Also: XOR enumeration skips printable-text blobs so EC/DSA textual children don't explode; per-node solver jobs capped to top 40 by prior. Verified: hex4 target #1; vigenere(lemon) #1; message DH #1; run_tests 32/32; matrix ALL 22 OK. Flagshape tests added (`test_flagshape.py`).
- E2b-fix5 (hex-layer family deep diagnosis): decisive depth-0 test showed 7/8 failures are expansion/gating (depth-0 solved), 1 vigenere CIPHER_FAIL (family length gate ≥12 letters → lowered to ≥8). Added a free fixed-point pre-pass in core (`_free_fixpoint`) that decodes unambiguous whole-buffer encodings (hex/base64/base32/binary) without depth/time-slice cost and pushes the fixpoint node while keeping the original as fallback; vigenere-family yields widened to 48; caesar yields all 25 shifts for ≤200-char mixed/non-alpha text; Enigma direct decrypts re-elevated to exact (trust 3 / 0.98); `hex-in-text` solver added for hex tokens inside prose. Fresh seed 20270306: 2/10 — categories 7× (d) top-cipher not solved + 1× (b) timed out, reported per instruction, not re-tuned. Regressions: run_tests 32/32, matrix all 22 OK, fuzz OK, test_flagshape 4/4.
- F0 (smooth-composite DLP): new solver `dlp-composite-smooth` jointly factors n via a checkpoint/backtrack Pollard p-1 ladder (B = 2^12..2^18, 12s cap) then solves the DLP per prime with Pohlig-Hellman over smooth r-1 (BSGS per prime power), combining via a generalized CRT for non-coprime orders; accepts only results that verify `g^x ≡ c (mod n)` and decode to printable bytes. Hex-without-0x parsing added to challenge.py (static `.digits(16)`/`.hex()`/`format(...,'x')` detection; decimal-first + hex-hypothesis fallback), plus DLP hint detection for `pow(g, SECRET, n)`. Fixtures: dlp512 / dlp1024 (hex), dlp_dec_g2 (decimal, g=2), dlp_neg_safe (1024-bit safe-prime negative), real_dlp pair (gen.py/output.txt). Verification: run_tests 37/37; matrix all 22 OK; fuzz OK; test_flagshape 4/4.
- G1 (multi-core execution): `--jobs/-j` CLI (default min(cpu_count,8); 1 = exact sequential). Node-level fan-out via one ProcessPoolExecutor per run (fork; `AUTOCRYPT_WORKER=1` blocks nested pools); worker runs one solver to its deadline and returns picklable yields; results merged in fixed registry order → identical output. `test_multijob.py`: 36/36 fixtures have identical top-3 (chain+plaintext) at -j1 vs -j4. Pool skipped for inputs <128 B. Ctrl+C cancels workers. Measured on 22 cores: slow cases remain deadline-dominated (mostly ≈1.0×, dlp1024 0.78×, mt19937 0.65× due CPU contention) — target ≥2× not met; parallel gains are limited by serial per-yield post-processing and global-deadline workloads. Regressions: run_tests 37/37, matrix all 22 OK, fuzz OK, flagshape 4/4.
- G2 (huge-N linear recurrence + derived key): static-AST recognizer extracts recurrence order/coeffs/base cases (symbolic `i-d` offsets, constant term), N (`int(2e7)`, `10**6`, named consts), modulus (`10**10000` etc.), verification hash and `bytes.fromhex` ciphertext constants. Fast companion-matrix exponentiation (O(k³ log N), 2.4s for N=2e7, M=10^10000) verified vs naive recurrence (`test_rec_naive.py` 20/20). Key-derivation matcher tries md5/sha1/sha256/sha512/blake2b over str/int/hex/big-endian forms, verifies against hash constant when present, derives XOR key (digest or hex, cycled) and accepts flag-shaped/English output; exact method emits `Cracked linear-recurrence + hash-xor`. Fixtures: real_seq/sequences.py, sequences_synth.py (order-3 + const, sha1, no verification), sequences_neg.py (no modulus, N=2e7 → quick "needs modulus" exit). Early exact path in solve_data runs before the full search for these signature sources. Verification: run_tests 40/40; matrix all 22 OK; fuzz OK; flagshape 4/4; multijob 38/38 equal. NOTE: real_seq is a synthetic fixture regenerated from the spec — the real file was not present in the repo, so G2's flag is synthetic, not a live capture.
- G1b (early exit on verified exact recovery): verified-exact rows (known-prefix/full-buffer flags, confirmed attacks, exact decodes, non-flag verified verdicts) now stop expanding new nodes after a configurable grace window (default 1.0s, `G1B_GRACE`), cancel pool futures, rank, and exit — junk accidental prefixes remain blocked by the fix4 full-buffer rule. Added per-solver timing + first-exact metrics (`--verbose`). ASCII-text blobs skip the multi-process precompute to avoid contention (mt19937 j4 ≈ j1). Post-change table (j1/j4): ec 1.30/1.30, dh 1.49/1.47, enigma 2.36/2.27, dlp1024 15.88/15.42, hash 30.23/30.23, fr 1.89/2.10, mt 1.25/1.28, t 3.79/3.71, pp1 0.53/0.54, ecdsa 1.25/1.23 (verified repeats: mt j4 1.28s). Most slow cases now finish in 1–3s; dlp1024 and hash remain >5s (dlp ladder cap + hash brute). run_tests wall ≈ 2m47s (40/40); matrix 22/22; fuzz OK; flagshape 4/4; multijob 38/38 equal.
- H1 (hex-layer family fix, diagnosis seed 20270306): root causes found by diagnosis — (a) `_free_fixpoint` branch-order bugs: pure binary `0/1` buffers were eaten by the hex branch (all hex digits) and uppercase base32 blobs by the base64 branch, so the free strip never fired on binary/base32 stacks; (b) the low-printability guard discarded the final legitimate strip (binary→ciphertext) instead of keeping it; (c) fingerprint classified XOR ciphertext with control bytes as `ascii-text`, gating out the XOR solvers; (d) a wrong-key `Cracked short XOR` output that merely looked flag-shaped hit `is_flag` + immediate early exit, returning junk and discarding the true recovery. Fixes (all general): disambiguated fixpoint branch order (binary before hex; hex rejects pure 0/1; base32 before base64), keep-and-stop on opaque payloads, control-byte blobs are `mixed` not `ascii-text`, early flag exit requires confidence ≥0.95, `clear_english` rejects non-prose punctuation (`$\`^~|` etc.), flag rows no longer lose the sort tie to `_english_ok` rows (engok jump applies to non-flag rows only). Verified: seed 20270306 matrix 10/10 (was 2/10); FRESH seed 20270307 depth 1-2 → 10/10 (target ≥9/10 met); depth 3-4 → 9/10 report-only (one atbash_L4 tie flake, solves rank 0 on isolated rerun). Regressions: run_tests 40/40; matrix 22/22; fuzz OK; flagshape OK; multijob 38/38 equal.
- I1 (timing-robust adaptive budgets): evidence first — seed 20270308 d34 grid, 3 reps idle vs 3 reps with 4 CPU-contending autocrypt copies: pre-fix cases 3 (atbash_L4, empty top under load) and 5 (xor_L4, two different junk tops) differed. Root causes: (a) `solve_xor_repeating` abandoned the whole joint product on wall-clock expiry and cut the key-length loop at different points under load → different best key; (b) deep-chain nodes (e.g. atbash_L4 leaf) starved behind shallow nodes when the root's job list consumed the global deadline under contention; (c) the G1b post-exact grace was TIME-based, so the number of trailing nodes drained (and with it the weak junk tail of the result set) depended on machine load — surfaced as ecdsa_reuse j1/j4 top-3 flakiness in multijob. Fixes: XOR enumeration is now work-based (fixed iteration counts — full bounded product, all key lengths; time only as outer cap); per-solver slice gains a ONE-time up-to-2x extension when a solver still yields near its slice end and the global deadline has room; free-fixpoint node priority no longer penalized (×1.0 + 0.1·depth) and decoder-chain expansion depth boost raised (0.12 → 0.22); post-exact draining is now deterministic — at most 8 extra nodes, no new expansions after exact found. After fix: seed 20270308 d34 idle vs loaded = 0 diffs (all 10 cases stable, identical tops); ecdsa_reuse top-3 stable across 3×j1 + 3×j4 with j1≡j4. Fresh measurement: d34 seed 20270308 → 7/10 (report-only; failures idx3 atbash_L4 rank2, idx5 xor_L4, idx7 vigenere_L4), d12 seed 20270309 → 10/10 (target ≥9/10 met). Regressions: run_tests 40/40; matrix 22/22; fuzz OK; flagshape OK; multijob 38/38 equal.
- E2b2 (blind set 3, seed 20270630, one run, no changes): 22/25 (88.0%) — BELOW 90% target, not fixed (per instruction). Failing cases: `xor4` (rank None; top hex -> repeating-key XOR(key_hex=60623a62) → 'TUst{p3-_ct'e}' junk), `rsa_factored` (rank 4; top scytale/… junk chain vs expected small-factored-RSA flag), `atbash_rot13` (rank None; top affine(a=19,b=8) junk vs expected atbash∘rot13). Depth split: none of the failures has ≥3 encoding layers; the 3-layer (b64_hex_b64) and 4-layer (hex4) cases both passed — the misses are NOT the known 4-layer weakness (xor4 is 1 layer, rsa/atbash_rot13 are 0). Wall time ≈ 4m46s for 25 cases.
- E2b3 (blind set 4, seed 20270901, one run, report-only): 25/25 (100%) — all rank #1. Only generator adaptation: rsa_small modulus raised to 192-bit primes so the seed's short flag still satisfies m³ < n (same generator otherwise).
- E3a REBUILT (realistic CTF pairs, fixtures/e3/, synthetic flags, seed 20270710): now 15 pairs (c01-c15) written in realistic style — flags are read from `flag.txt` (never provided) and are ABSENT from every file; generation asserts no flag or its base64/hex/reversed encodings appear in any pair file. Builder lives in e3_section.py (imported by make_fixtures.py). New pairs: c09 common-modulus RSA, c10 Hastad e=3, c11 Franklin-Reiter, c12 DH shared secret→sha256 key XOR, c13 md5 weak-password hash crack, c14 LFSR keystream (taps/seed visible), c15 single-byte XOR binary-ish.
- test_e3.py strict harness (one run, report-only): PASS only if top row is not as-is/source echo and contains the exact flag. Table: c05 PASS (genuine RSA small-e exact root, but wall 30.5s — no verified-exact early exit, is_flagish fails on underscore-heavy body → full budget burned; RSA solver itself ~0s). c06 FAIL → FIXED this turn (see below). All other pairs FAIL with true plaintext ABSENT (no solver produced the flag): c01/c02/c03/c04/c07/c08/c12/c13/c14/c15 = source-text classical junk only (true absent); c09/c10/c11 = RSA-family absent (common-modulus/Hastad/FR not produced in 30s); budget >35s violations: c06, c10, c12 (30s cases near cap).
- RSA p/q fix (allowed c06-type): RSA-extra prior now also matches `p`/`q` labels and ≥4-int numeric text; `solve_rsa` derives n=p·q and decrypts directly via φ(n) when p/q are given (no factoring); unlabeled 4-int `p q e c` fallback added. Fresh family seed 20270720 (10 cases: labeled/unlabeled, decimal/hex, p/q order swapped, with/without n): 10/10 rank #1, each <2s. c06 now solves in 0.3s.
- E3 SOLVABILITY PROOF: independent ref solvers in fixtures/e3_ref/cNN_ref.py (human-style, parse pair files only, no autocrypt imports): all 13 failing pairs ref-solve OK (≤0.05s each) → no broken pairs; the tool failures are real. c01/c10/c11 ref bugs were fixed (pair files unchanged).
- E3 INVOCATION CHECK (c15/c13/c14): `python3 autocrypt.py challenge.py output.txt` (multi-file, merged via challenge.load) and output.txt alone both run and produce identical junk — neither works; combined invocation does not inject .py hints.
- E3 PARSE DIAGNOSIS groups (evidence: blob head + solver_times from diag_e3.py): (S, 8) c02/c03/c04/c07/c08/c10/c12/c14 — data extracted but right attack not attempted: key/shift/private constants live only in challenge.py (no hint propagation); c10 Hastad label shape (e1/e2/e3) unsupported; c14 needs a crib parameter; c12 secret only derivable from the source constant. (A, 3) c09/c11/c13 — solver ran (RSA/common-modulus, franklin-reiter, hash) but attack produced no row. (P, 2) c01 (rot13-mangled hex with envelope never recognized) and c15 (space-separated hex not extracted as hex; single-byte solver never got clean bytes).
- c05 FIX: verified-exact/flag paths now accept fully-printable flag-shaped exact recoveries via `_flagout_ok` (regex + printable gate) instead of only `is_flagish()`. Fresh family seed 20270721 (10 RSA small-e exact-root flags, underscore/leet-heavy bodies): 10/10 rank #1, each <3s wall (c05 itself now 0.24s vs 30.5s).
- E3 fixes (A-group + c15): common-modulus labels now accept space/`:`/`=` delimiters (decimal & 0x-hex, any e1/e2/c1/c2 ordering): family seed 20270730 → 10/10 <3s. Franklin-Reiter generalized to m2=a·m+b via modular elimination (labels a/b/diff, decimal/hex, any order; b=0 documented as unsolvable): family seed 20270731 → 10/10 <3s. Hash crack: label-aware hash-line parsing (bare, `hash=`/algorithm=, `:`), plus hash→XOR pairing with the cracked password's hexdigest (skip hash line, inline `hash:ct` form): family seed 20270732 → 10/10 <3s. Separated-hex single-byte XOR: fingerprint + decoder + free-fixpoint now accept whitespace/,/; /0x-separated whole 1-2 hex-digit tokens (strict full-token rule so English words never classify as hex — fixes an E-substitution hang); family seed 20270733 → only 2/10 <3s (TARGET NOT MET: most variants rank #1 but finish in 3-15s; the slow path is scheduler latency to the decoded node, not the attack).
- Negative tests (text with similar labels/numbers/hex-ish tokens): 0 false positives.
- Regression causes fixed along the way: K0 `os` shadow bug (explicit `--jobs` crashed); `@solver` decorator accidentally left on `_fr_recover_general`; `base_method` NameError ordering; final recovered cap exempting verified statistical rows (hash fixture). All suites green.
- J1a (atbash_rot13 fix): evidence — affine(25,12) (the true composed map) was never yielded: `solve_affine` ranked all 312 keys by English-only evidence and kept top 2, and junk affine(19,8) got a flag-shaped lift to .97/trust2. Fix: affine now scores every key by max(English, flag-plausibility) — and for flag-shaped outputs by the leet-body dictionary fraction (flag_plausibility is not word-aware: true body 1.0 vs junk 0.33) — yielding top 10; core's leet-body tie-break then ranks true #1. Family seed 20270701: 10/10 (7 named + 3 compound compositions; both compound misses fixed). Regression-relevant core changes (verified-flag-out predicate) also fixed an intermittent silent drop of RSA yields (NameError order).
- J1b (rsa_factored fix): evidence — TRUE at rank 4 (conf .55 trust3) below junk decode chains (.62-.64): verified RSA recovery 'ged{a1}' was demoted because is_flagish fails on short bodies and the text lacks `=,;:` punctuation. Fix: verified recovered rows whose output is flag-shaped and printable (≈ascii, ≥90% printable) are confirmed (.98) and exempt from the final unconfirmed-recovered cap. Also: unlabeled "n e c" parsing fallback (3 ints, n>c, e≥2, only when no labeled values), and RSA solver gets an extended slice (30s, global-capped) when a labeled modulus is present so 96-128-bit factoring isn't cut at 4s. Family seed 20270702: 10/10 (decimal/hex/unlabeled mix; large-n cases use synthetic p-1-smooth primes, labeled synthetic in the generator).
- J1c (xor4 diagnosis only, no fix): per-column printable survivors 60-66; shape∩printable = [46,1,35,53] per column (col1 nearly pinned). The true combo is ABSENT from the joint space: col2's true byte (0x7e) is position 29 in the merged per-column list → cut by the cap-24 truncation before the joint product is even formed (product 24^4=331,776). Proposal: per-column cap includes ALL shape∩printable candidates when ≤128 (union, not top-24); product ≤ ~85k here; evaluate all with plain_text_score presort + _flagaware on top ~5000 (raise from 300); guard with a 2M product fallback; estimated added cost <1s for n≤32 (see PROGRESS Next 0).
- K0 (strict exception mode): `AUTOCRYPT_STRICT=1` / `--strict` — any unexpected solver exception (NameError/AttributeError/TypeError/UnboundLocalError/KeyError/IndexError/ImportError/AssertionError) is recorded (solver name + traceback), printed with `--verbose`, and in strict mode makes the run exit non-zero after finishing; expected rejections (ValueError/expired/parse) stay quiet. run_tests.sh now exports STRICT. First strict sweep found ONE real silent bug: `straddling-checkerboard` raised IndexError (row1 length 9 vs digit 9) on fr_unlabeled/lcg — fixed with bounds guards. Strict sweep: run_tests 38→40 PASS after fix; matrix 22/22; flagshape OK; hexfamily fresh d12+d34 10/10; blind3 24/25; fuzz OK.
- J1c (xor narrowing implemented): per-column caps keep ALL shape∩printable candidates when ≤128 (union); joint product capped at 40k (deterministic trim of widest shape-only column when over); presort key now adds 4.0×leet-body-dict-fraction (the real discriminator); deterministic leet-body tie-break among equal objective scores; L=5 joint gate extended to n≤60; seed-product ascent (≤128 seeds) for L≥4 short flags; high restart counts restricted to non-textual nodes (this also restored fuzz timing). Verification: fresh seed 20270703 xor family → 7/10 (target ≥9/10 NOT met; failures all L=3/5 variants whose true byte sits deep in a wide per-column shape list and is excluded by the 40k trim/presort; several cases also hit the 15s global budget). Flake idle-vs-loaded on the family: 0 diffs. Blind3 seen-data regression: 23/25. fuzz OK. Accepted as the final result for L≥4 short flags (inherent ambiguity); beam-search follow-up deferred.
- ENV (env bring-up): no system Python on this machine (Microsoft Store app-alias stubs); interpreter managed by `uv` — `uv python install 3.12.16`, project `.venv` created via `uv venv`, and a `python3.exe` shim (copy of `python.exe`) placed in `.venv/Scripts` so the bash harness (`run_tests.sh` etc. all invoke `python3`) resolves. Installed `pillow==13.0.0` into the venv for `lsb_png` (was failing on missing Pillow). This is the prerequisite that made 40/40 reachable at all.
- H2 (hint propagation from challenge.py): `analyze_source` now also returns `dlp_hint` (inline `pow(g, <int literal>, n)` exponent → `a=<int>`, and `pow(g, SECRET, n)` secret detection) and `byte_hints` (str/bytes Constants named key/secret/password/salt → utf-8/raw hex). `_hint_lines()` emits additive `name=value` markers (shift/seed/`key=0x…`/`name_bytes=0x…`/`a=…`, plus DH p/g/A/B/enc restoration when an inline-pow exponent is present) appended to every return path. New hint-consumer solvers (`hint-secret-xor`, `hint-caesar`, `hint-vigenere`) fire with prior .99 only when their marker is present. Verified: `test_hints.py` 7/7 markers; E3 S-group c02/c03/c04/c07/c12/c13/c15 now green (were all true-absent).
- H3 (RSA/parse fixes): (a) **fr_unlabeled** baseline failure was NOT solver logic — a console-encoding crash (cp1252 `UnicodeEncodeError`) on U+FFFD in a recovered plaintext; fixed via `sys.stdout/stderr.reconfigure(errors="replace")` at top of `main()`. (b) **c10 Hastad broadcast**: three coordinated fixes — `solve_rsa` now accepts a single shared `e` (triples loop falls back to shared `e` per index); challenge.py token-matching strips `name = ` assignment prefixes before scanning for hex tokens (so hex-looking variable names like `c1` no longer corrupt label⇄value alignment); and the `labeled_lines` branch whitelist extended with `known_labels` so n1/n2/n3/c3 are captured. With all three, c10 PASSES. (c) `lsb_png` reachable via Pillow.
- Session regression confirmation (all green): run_tests.sh **40/40 PASS**; test_matrix --both **22/22 rank #1**; test_multijob **38/38 equal** (j1 vs j4 identical top-3). E3 strict harness: PASS c02, c05, c06, c07, c10, c13, c15 (7); c12 solves but flagged BUDGET (55.7s > 35s); still failing c01, c03 (vigenere found but ranks #2 behind junk caesar), c04, c08, c09, c11, c14.
- R1-R2 (real online CTF challenges, 2026-11-05): curated **Sum-O-Primes** (multi-file .py + output.txt, hex output, RSA p+q leak where the leaked sum is named `x`) and **New Caesar** (custom b16 nibble-encode + single-char shift mod 16; .py + .enc) into `real_challenges/`. Fixed real bugs: (a) `RSA-sum-leak` solver only matched `p_plus_q/sum_pq/pq_sum/s` — real challenge uses `x`; extended matcher + `_pick` (now also `s`/`x`). (b) New Caesar had no solver — added `new-caesar-b16` (longest contiguous `[a-p]` run to avoid hint-line leakage from `key_bytes=0x62`, brute 16 shifts, nibble-pair decode, picks most-printable). Recovered real flags: `picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_24929c45}` (Sum-O-Primes) and `picoCTF{et_tu?_5723f4e71a0736d3b1d19dde4279ac03}` (New Caesar, key `b`). Added `run_tests.sh` rows `real_pqsum`/`real_newcaesar`.
- E4 (challenge.py print-label extraction): new `_print_data_args()` handles f-string prints (`print(f"n = {n}")`), list/tuple prints (each element its own label), and f-string hex field specs (`{n:x}` → marked hex). Whitelist expanded (`e/p/q/enc/msg/message/s`...); labeled-line hex detection consults `hex_labels` (all-digit hex like `0x10001` no longer misread as decimal); print-order token fallback filters all-letter prose tokens. `test_e4.py` 10/10 rank #0 <0.5s; real Sum-O-Primes/multiprime still solve.
- E5 (`--explain` flag): new `explain.py` maps each chain layer (with params) to a plain-English sentence (~120 templates; fallback for unknown/long-param solvers; `chr(98)`→`b`). Wired into autocrypt.py (`--explain` prints indented lines under each ranked result). `test_explain.py` 7/7 incl. CLI smoke on Sum-O-Primes.
- E7 (`--fast`/`--deep`): Context gains `speed`/`heavy_names`; per-solver slices + adaptive extension scaled by speed; `--fast` (speed 0.5) skips heavy brute-force solvers (`dlp-composite-smooth/hill-2x2/enigma-m3/hash-crack/vigenere-brute`); `--deep` (speed 2.0) raises `max_depth` 6→9. Plumbed through `solve_data`→`search(max_depth=)`. Fixed latent `--verbose` bug (`_search_t0` → `ctx.search_t0`). `test_e7.py` 4/4 PASS.

## Session 40 (2026-11-08) — updater reinstall failure no longer swallowed (install/update path)

Fixed a real bug in the self-update path: `_maybe_reinstall_after_pull` ignored
pip's return code and used the wrong cwd, so a failed post-pull reinstall was
silently reported as a successful update. `_update_git` now uses the git root as
the pip cwd and exits nonzero when the reinstall fails. Tests extended to cover
both the editable-installer layout and the reinstall-failure path. See LOGS S40.

## Session 40.2 (2026-11-10) — remaining install/update fixes (all 10 audit findings addressed)

Completed the rest of the confirmed install/update-path fixes:
- `do_update()` dispatch: cfg branch trusts only a `repo` path that is itself a
  git checkout; bare-checkout fallback requires the package dir to be a direct
  child of the git root (`<repo>/autocrypt`) so an index install inside an
  unrelated ancestor git repo is no longer misclassified as a source checkout.
- `install.sh`: Python-candidate loop skips `<3.12` interpreters and continues to
  later candidates (no hard-abort on first found); PATH persistence also writes
  `~/.bash_profile` (macOS login shells).
- `install.ps1`: `$v.Split('.')` guarded against `$null`/whitespace/non-numeric;
  User PATH idempotency is now exact per-entry comparison (split on `;`), not
  substring match.
Both installers pass syntax checks; updater tests pass; full standalone suite
re-run confirms no regression (only known pre-existing BKLG-22 flaw). See LOGS
S40.2.

## Session 40.3 (2026-11-10) — labeled-LFSR solver + version bump

Added `lfsr-known-fields` solver for the `LFSR Initial State / Taps /
Encrypted Flag` format (parses the three fields, tries every convention,
reports the readable decryption). Regression `tests/test_lfsr_fields.py` passes
on a synthetic c14-convention instance. Version bumped to `0.2.0`. Honest note:
the exact pasted 64-bit instance does NOT decode under any standard LFSR
keystream convention (best printable ~56-62%, no flag marker), so it likely uses
a non-standard generator or malformed data. See LOGS S40.3.

## Next
0. Real-challenge expansion (R-series, seed theorem with new real challenges): (a) more single-file RSA variants — Wiener (small d), close-prime Fermat, Håstad broadcast, shared-prime, dp/dq leak, common-modulus (several already have family tests; validate against real challenge data); (b) more multi-file pairs where the parameters/keys live in challenge.py (strengthen hint propagation for e/ct/enc variables, AES modes, RSA keys from `RSA.construct`/PEM); (c) hash-crack + XOR pairing on real data; (d) re-run the full real corpus after each solver addition and log regressions. Keep `real_challenges/` as the isolated, untrusted-data corpus; add new fixtures to run_tests as they stabilize.
1. E3 cycle 3 (remaining failures): (a) c03 rank #2 — vigenere key `k3y` is recovered but a junk caesar row outranks it; likely a ranking/prior-only issue, not true-absent; (b) c09 common-modulus and c11 Franklin-Reiter still fail in the E3 pairs despite family tests passing 10/10 — the pair invocations trip a condition the families don't (investigate the actual c09/c11 pair shapes; the A-group fixes covered delimiter/ordering, so the gap is elsewhere); (c) c01 rot13-hex envelope extraction; (d) c14 LFSR crib handling; (e) c08 reverse+caesar custom; (f) c04 repeat-XOR over short body; (g) sep-hex c15 <3s scheduler latency (target 10/10).
1. E6 - performance pass: profile 10 slowest cases, expired() checks on every long loop, keep every case under timeout+2s; report before/after seconds.
2. E8 - README.md: install, usage, full technique list, limits (strong modern crypto not breakable), .py+.txt workflow, "how to add a solver".
5. E8 - README.md: install, usage, full technique list, limits (strong modern crypto not breakable), .py+.txt workflow, "how to add a solver".

## Deferred
- J1c L≥4 short-flag repeating-XOR: 9/10 after Session 29 (gated broad ascent over the shape space). The single remaining case (`xor5_w2`) is a genuine ambiguity — a wrong 5-byte key decodes the ciphertext to an equally-plausible leet flag that out-scores the true one under the objective. Revisit only if E3 shows real cases with that shape.

## Known bugs
- AES/Fernet need optional pycryptodome/cryptography (skipped gracefully; no pip here).

## How to test
- `bash run_tests.sh` -> 43/43 PASS (added real_pqsum + real_newcaesar; even_e timing flake intermittent ~20.3s, passes on re-run) (message.txt -> academy{dh_s3cr3t_913ddd75}, rsa_even, lfsr, t.txt, c1_*, z85, custombase, crt, pp1, ec/ecdsa/dsa, shared_prime, dpdq, pqsum, even_e, fr_*, lcg, mt19937, dh_dlp, rc4, hash, dna/twosym/braille/b32hex, lsb_png, wav_lsb, enigma_direct, dlp512/dlp1024/dlp_dec_g2/dlp_neg_safe/real_dlp, real_seq/sequences_synth/sequences_neg; optional aes/fernet rows SKIP when libs absent).
- `python3 test_matrix.py --both` -> 22/22 rows rank #1.
- `python3 fuzz.py` -> ALL FUZZ CASES OK.
- `python3 test_flagshape.py` -> FLAGSHAPE: ALL OK.
- `python3 test_multijob.py` -> MULTIJOB: N/N equal (j1 vs j4 identical top-3).
- Hex-layer family: `python3 test_hexfamily.py <seed> --matrix` (mixed), `--grid d12|d34` (depth split).
- XOR family: `python3 test_xorfamily.py` (seed 20270703: 9/10, one L≥4 short-flag ambiguity remains — see Session 29).
- Blind seen-data regressions: `python3 test_blind3.py` (24-25/25), `python3 test_blind4.py` (new seeds, report-only).
- Strict mode: any of the above under `AUTOCRYPT_STRICT=1` (or `--strict`) fails on unexpected solver exceptions; `run_tests.sh` already exports it.
- Flake checks: `python3 flakecheck.py <seed> --grid d34 [--contend]`, `--xorfam` for the XOR family.
- Targeted: `python3 autocrypt.py fixtures/trifid_sample.txt` etc. (samples in the repo `fixtures/` folder).

## Session 8 (2026-11-05) — more real CTF challenges: RSA p+q leak + New Caesar b16 cipher
- Real Sum-O-Primes (picoCTF, multi-file .py+output.txt, hex): RSA p+q leak where the sum variable is named `x` (not `s`/`p_plus_q`/`sum_pq`). Added `x` to the `RSA-sum-leak` solver's matcher + `_pick`. Now recovers `picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_24929c45}`. First multi-file hex RSA pair solved.
- Real New Caesar (picoCTF, .py+.enc): custom b16 nibble-encode + shift mod 16 (ALPHABET = a-p, 1-char key). Added new solver `new-caesar-b16` (longest contiguous [a-p] run, brute-force 16 shifts, best printable). Recovers `picoCTF{et_tu?_5723f4e71a0736d3b1d19dde4279ac03}` with key `b`. Fixed hint-line `[a-p]` leakage (key_bytes=0x62) by using longest-run extraction.
- New run_tests.sh rows: `real_pqsum`, `real_newcaesar`.
- Solver files touched: solvers_pack3.py (solve_sum_leak: `x`; new solve_new_caesar). Test file: run_tests.sh.

## Session 9 (2026-11-05) — E4: challenge.py print-label extraction
- f-string prints, list/tuple prints, f-string hex field specs now labeled per-value (was x1/x2/x3 / single x).
- Labeled-line whitelist + hex_labels + all-letter token filter (0x10001 / banner-word fixes).
- New family test_e4.py 10/10 rank #0 <0.5s.
- run_tests full regression green.

## Session 10 (2026-11-05) — E3 to 15/15: c01/c08/c11/c14 fixed

- c11 Franklin-Reiter: `core.py` breaks after the first `recovered` yield of a
  solver, so `solve_related` (solvers_more.py) yielded its "fixed" sibling
  (junk) before the "original" message (the real flag). Reordered to yield
  original-first; the flag now survives the break. E3 c11 rank #0.
- c01: new `hex+rot13` solver (solvers.py) — restores ROT13-rotated hex
  letters (n..s → a..f) from even ≥16-char runs, emits the restored hex string
  so the existing hex → base64 layers chain on. E3 c01 rank #0.
- c08: base64 label-prefix tolerance in `core.fingerprint` + `solve_base64`
  (strip a leading `<name> = ` before the alphabet / mod-4 checks; original is
  always tried first so existing inputs are unchanged), plus a caesar-shift
  fallback that recovers a `caesar(b64)` layer when the direct decode is
  opaque (non-text). E3 c08 rank #0.
- c14: new `hint-keystream-xor` solver (solvers.py) — when the challenge emits
  both a `keystream_hex=`/`keystream=` and a `ct=` label, it XORs the
  keystream with the ciphertext. Prior 0 unless both markers present. E3 c14
  rank #0.
- E3 harness now 15/15 PASS, all rank #0, within budget.
- Regressions: run_tests 43/43; test_matrix --both 22/22; fuzz 12/12;
  test_multijob 38/38 equal. No collateral failures.
- Created `things_it_cant_solve.txt` tracker (mutated c01/c08/c14; lists the
  remaining documented known limits).

## Session 11 (2026-11-05) — reported challenges: e=3 RSA, flag-body cipher

- e=3 RSA ("e should be larger", N≈1006 digits, c≈1009 digits): the small-e
  exact-root path in `solve_rsa` required `c < n`, so an *unreduced* m^3 (a
  perfect cube) that exceeds n was never tried. Relaxed the gate to attempt
  `_integer_root` whenever e ≤ 17, guarded by the exact `m**e == c` check
  (safe; reduced ciphertexts are not perfect powers). Now recovers
  `academy{e_sh0u1d_b3_lArg3r_35f26e1a}` at rank 0.
- Flag-shaped input whose body is ciphertext (`academy{xmjnndiboczmpwdxjiqaptvumw}`):
  autocrypt short-circuited to the as-is row (conf 0.99) and never decoded the
  body. Fixed in core.py + solvers.py: the known-prefix early return is now
  gated on body plausibility (`_ASIS_BODY_PLAUSIBLE`), keeping the as-is row at
  the 0.96 floor and continuing the search; `is_flag` confirmation rejects echo
  (byte-identical) candidates and only confirms classical transforms of an
  already-flag-shaped input when they improve body plausibility. New
  `flag-body-decode` solver tries Caesar/ROT13/atbash/Vigenere on non-plausible
  bodies and preserves the `prefix{}/}` shell. Target now rank 0 via
  `flag-body caesar(5)` → `academy{crossingtherubiconvfuyazrb}`; genuine
  plaintext flags still pass through unchanged.
- e=65537 RSA with a 270-bit modulus (generic 135-bit primes): documented as
  unresolved hard-factoring (p−1/p+1/Fermat/rho infeasible in pure Python; out
  of scope). Added to things_it_cant_solve.txt and README known-limit note.
- Regressions: run_tests 43/43; matrix 22/22; fuzz 12/12; multijob 38/38;
  flagshape OK; E3 recovered across the last (c14 remains the pre-existing
  harness echo-heuristic "rank0" label, unchanged).

## Session 14 (2026-11-05) — e5 270-bit RSA SOLVED (external factoring)
- Chain `real_challenges/e5_270rsa_rev/` (270-bit n, e=65537, c) decrypted.
- Pure-Python factoring was exhausted (trial-div/Fermat/p±1/rho/ECM); GMP-backed
  `primefac` ECM/SIQS too slow in the window.
- Factored externally via **factordb**: p=2074606527507983503944226222695401999839
  (131b), q=659880377875535146491994798968813949893149 (139b); p*q==n.
- Decrypted bytes were **reversed** (challenge `_rev`) →
  **FLAG = `academy{sma11_N_n0_g0od_a3ac7152}`**.
- No solver code changed; run_tests 43/43 baseline unchanged. Solution in
  `_e5_solved.txt`; `things_it_cant_solve.txt`/`session.md`/`LOGS.md` updated.
- Open note: native solver lacks a QS/GNFS path — >192-bit semiprimes are
  external-only (documented in README known limits).

## Session 21 (2026-11-07) — RSA battery (9/11); Coppersmith partial-p solver
- Added **`rsa_battery.py`** (promoted from scratch `_rsa_battery.py`): an
  11-class raw RSA attack battery. Fixed a `smooth_prime()` generator hang
  (unbounded random small-prime multiply never terminated) — now finds the
  smooth prime instantly.
- Battery baseline: **9/11 solved.** PASS: baby_pq, small_e_overflow,
  small_e_exact, wiener, pm1_smooth, fermat_close, common_modulus, hastad,
  shared_prime. FAIL: **boneh_durfee** (d≈N^0.30 — beyond Wiener and above
  Boneh–Durfee's theoretical bound N^0.292) and **partial_p** (needs a
  lattice attack). Both documented in `things_it_cant_solve.txt`.
- Added **`lattice.py`** (pure-Python): LLL basis reduction + Coppersmith
  univariate for known-high-bits-of-p. Verified on synthetic factor pairs.
- Wiring (in progress): `_rsa_values` now parses `p_high`; `solve_rsa` gains
  an `RSA partial-p (Coppersmith)` branch via `_recover_p_partial`; tuning
  lattice size so the 1024-bit battery case fits the 25s per-case budget.

## Session 22 (2026-11-07) — Coppersmith partial-p SOLVED (battery 10/11)
- Root cause of the partial-p failures was NOT the lattice bound — it was two
  real bugs in the new lattice machinery:
  1. **Polynomial root-finder bug**: the CRT-based root finder took the
     combinatorial cross-product of roots modulo each small prime and capped
     the candidate set at 512 — the true root's residue was routinely dropped,
     so recovery looked like "no roots" even when the lattice bound was met.
     Replaced with **Cantor–Zassenhaus** root-finding modulo a single large
     prime (`czroots.py`), which handles huge (5000-bit) coefficients exactly
     without factoring (verified: finds known roots in random 5000-bit-coeff
     polys).
  2. **LLL speed**: swapped `Fraction`-based Gram–Schmidt for
     `gmpy2.mpq` (~5x faster on Coppersmith-size lattices, identical output).
- Coppersmith `coppersmith_partial_p` now defaults to `mm=3, tt=1` (dim 5)
  with an automatic dimension-escalation ladder. Real 1024-bit partial_p case
  recovers in <1s (8/8 random seeds). `_recover_p_partial` now tries the
  inferred m first (was ascending from m-9, wasting ~19 lattice reductions).
- **Battery: 10/11.** partial_p PASSES via `RSA partial-p (Coppersmith)`;
  the only remaining FAIL is boneh_durfee (d≈N^0.30 is ABOVE Boneh–Durfee's
  theoretical N^0.292 bound ⇒ generator/parameter issue, documented).
- Regression maintained **43/43 PASS** (run_tests.sh). README battery baseline
  updated to 10/11; gaps tracker updated.

## Session 23 (2026-11-07) — partial-p generalization to unbalanced primes
- Generalized `_recover_p_partial` (solvers.py) so partial-p recovery also works
  when p is NOT ~sqrt(n) (unbalanced prime factor). The lattice itself already
  handled it; the gap was the hypothesis sweep: the β-grid (p ~ n^beta)
  didn't cover the true low-bit count m, and each wrong m ran an expensive
  escalated lattice.
- Sweep rework: interleaved upper/lower imbalance hypotheses (balanced first),
  cheap `mm=2` single-dimension tries (verifiably ~2.5x faster than mm=3, and
  sufficient for both balanced and unbalanced recoveries), a hard cap
  [_P_MAX_TRIES=30] on lattice attempts, plus an escalated mm=3 fallback on the
  nearest candidates for borderline balanced bounds.
- Fixed `rsa_battery.py` to invoke autocrypt via `sys.executable` (was the
  hard-coded `python3`, which is a stub on this machine → JSON parse failure).
- Verified: unbalanced 852-bit n / 512-bit p (m=160) recovers in ~13s;
  battery stays 10/11 with partial_p PASS; balanced partial_p still <1s.

## Session 24 (2026-11-07) — hardening + portability (battery 10/11)
- **Bugfix: czroots crash on a root-finder prime dividing the leading coeff.**
  `find_roots` now chooses prime `P > bound` **coprime to the leading
  coefficient** (skips `P` where `L % P == 0`), so `pow(L, -1, P)` never
  raises ValueError.
- **Bugfix: escalated-fallback no-op.** After the cheap sweep marks every m
  tried, the escalated fallback's filter `[m for m in order[:5] if m not in
  tried]` was empty → large-leak balanced cases silently skipped the fallback.
  Fixed by clearing the `tried` set before the fallback pass.
- **Deadline-abortable LLL.** `lll(basis, check=...)` now takes a `check`
  callback; when it turns falsy (deadline expired) the reduction aborts and
  returns `None`, so a high-dimension lattice can't hang for minutes past the
  per-case budget. Threaded through `_coppersmith_try`.
- **Sweep ordering hardened.** Restored the proven cheap-first hypothesis sweep
  (balanced first, interleaved upper/lower imbalance) with a small escalated
  fallback *only* on the closest candidates — avoiding burning the whole
  budget on escalation of a wrong m. Unbalanced cases now recover in ~8-17s.
- **New regression `test_partial_p.py`** — 13 cases (balanced + unbalanced
  keys, several m/leak sizes) exercising `_recover_p_partial` directly.
  All 13 pass (unbalanced 1024/614 m=192 in ~17s; balanced 1024/512 m=192 in
  ~36s).
- **Subprocess portability.** Replaced hard-coded `"python3"` with
  `sys.executable` across the test scripts and battery (python3 is a stub on
  this machine → empty stdout → JSON parse failure); fixed a mis-injected
  `import sys` left inside a docstring by an earlier patch script.
- Verified: battery **10/11** (partial_p PASS), test_partial_p **13/13**,
  E3 **15/15**.

## Session 25 (2026-11-07) — RSA e=1/Rabin, non-flag plaintext scoring

- **Non-flag plaintext scoring.** A verified exact RSA/crypto attack that decrypts
  to printable, non-flag-shaped plaintext (real encryption, not a `flag{...}`
  shell) now scores 0.98 and ranks at 0 instead of being demoted below the display
  floor. Ambiguous / non-printable recoveries remain capped at 0.55. This makes
  the solver recover genuine decrypted plaintext regardless of flag format.
- **RSA e=1 (identity).** `e==1 && c<n` ⇒ plaintext is `c`; decoded and reported
  decisively.
- **RSA Rabin (e=2).** After factoring, decrypt via Tonelli–Shanks square roots
  mod p/q + CRT; all four roots are emitted.
- **Tonelli–Shanks fix.** The sqrt update multiplied `t` by the stale pre-update
  `c` instead of `c_new = b²` (a tuple-unpacking bug), so some quadratic residues
  returned None. Fixed; brute-force QR sweep now 0/16516 bad.
- **New regression `test_rsa_extra.py`** — end-to-end e=1 and Rabin cases through
  `solve_rsa`; both pass in ~2s.
- Verified: battery **10/11** (partial_p PASS), test_partial_p **13/13**,
  E3 **15/15**.

## Session 29 (2026-11-07) — xorfamily short-flag search fix

- **Root cause.** Two L=5 short-flag failures (`xor5_w0`, `xor5_w2`). The joint
  enumeration's product trim (to ≤40k) deletes the true key byte when it sits deep
  in a column's unigram ranking — short 3-byte columns carry too little per-column
  evidence to rank the true byte highly. The true key is in the shape-consistent
  candidate set but gets cut before it is ever scored.
- **Fix.** For L≥4/n≤60, run a broad, deterministic coordinate ascent over the
  full shape-consistent space and append its best result, so the true key is
  always evaluated even when the joint-enum trimmed it away. Gated to only run
  when (a) the raw shape product exceeds the trim threshold and (b) no shorter
  key (L≤3) already explained the blob as a strong flag — the latter keeps
  single-byte-XOR data (sephex) from burning budget on a spurious L=5 search.
- **Result.** xorfamily **9/10** (was 7/10 accepted). families **40/40**, E3
  15/15, E4 10/10 all confirmed. The remaining `xor5_w2` is a genuine ambiguity
  (a wrong key decodes to an equally-plausible leet flag that scores higher under
  the objective); not forced to avoid fragile scoring tweaks.

## Session 30 (2026-11-07) — show-all-results + dictionary word-list substitution solver

- **Show all ranked results.** The CLI/solver default `--top` was 5, so only 5
  ranked results ever displayed. Raised both defaults to 200 (`solve_data` and
  `--top`), so every ranked recovery surfaces.
- **Dictionary word-list substitution solver.** A monoalphabetic substitution over
  a corpus of single English words (one per line) cannot be solved by letter
  frequency (cipher words are unique) — but the per-word letter *pattern* is
  invariant, so aligning encrypted tokens against a dictionary pins the
  permutation. New `substitution-wordlist` solver runs AC-3 constraint
  propagation over word patterns (queue-based worklist + candidate-list cap,
  ~1.5s) and decrypts the flag phrase. Front-gated to large ascii-text corpora;
  skips inputs that are already plain English.
- **Recovery labeling.** The solver emits `cracked monoalphabetic substitution
  (dictionary wordlist)`, which routes through core's `recovered` retention path
  so the underscore/leet flag phrase isn't buried by the English-confidence gates.
  Fully algorithmic — no flag text is hardcoded.
- **New regression `test_substitution_wordlist.py`** builds a synthetic encrypted
  wordlist+flag and requires the decrypted flag at rank 0.
- **Result.** The study-guide+flag challenge from "things it can't solve 2" now
  recovers `perhaps_the_dog_jumped_over_was_just_tired` at rank 0 (≈100% corpus
  coverage). Rail fence case already rank 1. Regression: E3 15/15, E4 10/10,
  families 40/40, matrix OK, substitution PASS.
- **Still open (honest).** numeric 22-number message (no reversible mapping found;
  ambiguous), Vigenère/cipher pair (identical ciphertext, unknown key, no crib),
  and `rot13.txt` (ROT13 output is non-dictionary junk — random flag or extra
  unprovided layer). Tracked in `things_it_cant_solve.txt`.

## Session 40.4 — Medium-tier symmetric-key pack
- Four new solvers (DES / 3DES / Blowfish / ChaCha20) recover flags from
  known-key challenge format `key=... [iv=...] [mode=...] <hex ciphertext>`.
- Addresses the "train it more into medium stuff" goal with real crypto
  primitives beyond the classical ciphers already present.
- Robustness hardened via adversarial review (uppercase labels, CBC/CTR
  branches, ASCII-key fallback, algorithm-label guard, false-positive gating).
- Tests: `test_medium_pack.py` covers 10 checks incl. uppercase labels,
  CBC/CTR, ASCII key, label mismatch, and a no-crypto prose sniff.
- All pass; full suite shows no regressions (three failures confirmed
  pre-existing against HEAD).

## Session 40.5 — Fix Pollard p-1 / p+1 trivial-gcd failures
- `test_flaws2.py` reported 18 defects (8 p-1, 10 p+1): both factors smooth
  -> gcd == n -> None. Rewrote `_pm1` with a binary search on the first bound
  yielding a nonzero gcd (there exactly one factor is smooth -> proper factor),
  and `_pp1`/`_pp1_moment(B)` with shrinking-bound retry.
- `test_flaws2.py` and `test_flaws.py` both now clean (0 flaws, exit 0).
- Factoring/RSA families re-verified green; no regressions.

## Session 40.6 — Embedded base64-run extraction
- `solve_base64` missed base64 payloads wrapped in prose (labels/narrations):
  the fingerprint only classified all-base64 blobs, so the solver's prior was
  0 and it never ran.
- `core.fingerprint` now credits a base64 hypothesis when a maximal alphabet
  run decodes to readable bytes; guarded against prose false-positives (run
  must have a digit / non-alphabetic char, and decode must be >= 70% printable).
- `solve_base64` gains an embedded-run fallback scanning the raw buffer
  (whitespace intact, so prose stays split into short runs).
- Fixed an int-vs-bytes bug in the new solver path.
- New `tests/test_base64_embedded.py` (standard + url-safe embedded recovery,
  prose negative-control). All encoding/UI/factoring regressions pass.
- Version 0.5.0.
