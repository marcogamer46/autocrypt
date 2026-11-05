# autocrypt — work log

Chronological record of sessions and steps. Current status mirror: `PROGRESS.md`.
All work performed on 2026-10-31 (single continuous engagement).

## Session 1 — Backlog 1 (B1–B14)

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| B1 | Flag ranking: atbash on flag-shaped input ranks top (floor .95); regenerated `atbash_flag_shaped.txt` (old file had no braces). | core.py | atbash #1 FLAG |
| B2 | `_PERMUTING` rule: permuting recoveries allowed when clearly more plausible and flag covers >=75% of buffer (floor .98). | core.py | rail fence #1 FLAG |
| B3 | `_junk` filter: hide every non-flag result <0.60 unless exact recovery; flags always stay. | autocrypt.py | no sub-0.60 rows |
| B4 | Pollard p+1 (`_pp1`, Lucas fast-doubling) added to `factor_all` between p-1 and rho. | solvers_more.py | 3-safe-prime modulus recovered |
| B5 | Trifid cipher solver (9 alphabets x periods, decisive winner boosted). | solvers_pack5.py | classic + period-5 recovered |
| B6 | Nihilist cipher solver (9 squares x phrases x conventions; crib-driven exact recovery). | solvers_pack5.py | pure + keyed/crib recovered |
| B7 | Four-square cipher solver (6 keyword-pair hypotheses). | solvers_pack6.py | KEYWORD/SECRET recovered |
| B8 | Gronsfeld solver (per-column unigram digit keys). | solvers_pack6.py | key 31415 recovered |
| B9 | Straddling checkerboard solver (two layouts). | solvers_pack6.py | classic layout recovered |
| B10 | Z85 decoder; custom-alphabet base decoder (`alphabet=`/`data=`). | solvers_pack6.py | both FLAG |
| B11 | EC arithmetic + BSGS + Pohlig-Hellman DLP; ECDSA nonce reuse. | solvers_pack6.py | k,d exact |
| B12 | Merkle-Hellman knapsack (MITM + superincreasing greedy). | solvers_pack6.py | exact mask |
| B13 | LSB brute force over all 8 bit planes x channel combos; Pillow-only fallback. | stego.py | plane-1 FLAG |
| B14 | Enigma M3 (rotors I–V, reflectors B/C, plugboard, double-stepping) + crib brute force. | solvers_pack6.py | direct + cracked |

## Session 2 — Backlog 2 (C1–C20)

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| C1 | Decoder outputs with unknown flag prefix now rank (floor .95) instead of exiting; known-prefix/exact still exit. | core.py | t.txt chain recovered |
| C2 | bytes-literal / int-list / hexdump parsers. | solvers_pack7.py | round-trips |
| C3 | CRT solver (>=8 moduli) + radix-ascii (bases 2..36). | solvers_pack7.py | CRT FLAG |
| C4 | reverse-words / reverse-each-word; 4-layer tests. | solvers_pack7.py | all layers recover |
| C5 | DSA nonce reuse (q,r,s1,s2,h1,h2). | solvers_pack7.py | k,d exact |
| C6 | RSA shared-prime gcd + dp/dq-leak CRT-RSA. | solvers_pack7.py | both recover |
| C7 | Verified known-p+q and e=4 even-e roots recoveries. | (tests) | pass |
| C8 | Franklin-Reiter incl. unlabeled `c1 c2 diff N` order. | solvers_pack7.py | both recover |
| C9 | LCG recovery (unknown modulus) + MT19937 prediction (>=624 outputs). | solvers_pack7.py | exact |
| C10 | DH discrete log via Pohlig-Hellman over smooth p-1. | solvers_pack7.py | exact |
| C11 | RC4 key (native); AES modes + Fernet wrappers (optional libs); ECB repeated-block finding. | solvers_pack7.py | RC4 FLAG; ECB finding |
| C12 | Hash cracking (md5/sha1/sha224/sha256/sha384/sha512/ntlm MD4) with wordlist/builtin/digits/lowercase+digits<=4, salted. | solvers_pack7.py | md5 cracked |
| C13 | Vigenere-dictionary, Beaufort, Porta, autokey-with-crib, Hill 3x3 from 9-letter crib. | solvers_pack7.py | functional (noisy display) |
| C14 | DNA, two-symbol, Braille, base32hex, Crockford, swapped-case base64, ROL/ROR/add/sub (skip printable). | solvers_pack7.py | dna/twosym/braille/b32hex #1 |
| C15 | WAV LSB solver (all planes). | stego.py | plane-1 FLAG |
| C16 | `--json` all fields + status/failures; `--verbose` accept/reject. | autocrypt.py | json/verbose verified |
| C17 | run_tests.sh 32-case regression table. | run_tests.sh | 32/32 PASS |
| C18 | fuzz.py malformed/random/unicode cases. | fuzz.py | 12/12 OK |
| C19 | Per-solver 4s time share; hill-2x2 expired() checks; known-prefix early exit. | core.py, solvers_more.py | preserves all regressions |
| C20 | README.md grouped technique list + CLI examples. | README.md | — |

## Notable debugging detours
- B2: traced rail-fence “ranks #4” to blanket `_PERMUTING` skip; fixed with plausibility+coverage gates.
- B5: core re-assesses yields — solved with `_statistical`; fixed Lucas ladder MSB bug.
- B11: Pohlig-Hellman validated on curve mod 251 (order 250 = 2·5³).
- C1: changed exit semantics; regenerated layered `t.txt` fixture.
- C9: LCG gcd needed 2^k modulus candidates (m=2^31 edge case).
- C13: Porta tableau corrected to rotated 13+13 involution rows; Hill 3x3 matrix orientation fixed (blocks as columns).
- C17: classical-solver ranking stabilized — decisive winners bumped to 0.80 statistical; per-solver cap added in core.
- D3: the objective `plain_text_score` alone preferred corrupted XOR keys (k8y over k3y); `flag_plausibility` saturates at 1.0 for junk — switched to leet-body dictionary fraction as the discriminating evidence. `_repeat_xor_prior` had excluded printable-random ciphertext entirely (low IC), so the solver never ran; relaxing it required excluding text-like/encoded blobs to keep layered chains (c1_layers, reverse) fast.
- D6: transposition strong-recovery previously demanded an `english_confidence` gain — impossible for transpositions (letter multiset preserved), so the genuine rail never qualified; replaced with start@0 + span>=90% + leet-body dictionary gain. `solve_rail`'s top-3 cut dropped the genuine rail on longer flags (junk rails saturated plausible at 1.0) — now keeps 8 candidates ordered by dict evidence. Braille table lacked `{`/`}` (original fixture impossible to regenerate) — extended to full printable ASCII.
- D3/D6 fixture regeneration: `/tmp/opencode` wiped; rebuilt all 30 samples. Hits: Z85 tail-group encoding (n+1 symbols for n leftover bytes), EC/ECDSA point parsing (use gx/gy/qx/qy keys to avoid the G/Q-regex first-match trap), Enigma `plugboard=` line greedily swallowing the ciphertext (removed), pp1 as a 3-prime smooth modulus (RSA-extra only decrypts multi-prime), even_e with close primes + m⁴>n (forces the square-root path, avoids the small-e exact root label), DH with a primitive root, hash fixture without the `md5:` label, p-1 smoothness bounded by B=200000 for pm1.

## Session 3 — Backlog 3 (D1)

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| D1 | `english_confidence(text)` (quadgram + dictionary fraction) in scoring.py; core caps non-flag weak-English candidates at 0.55 and tie-breaks ranking by ec; classical solvers (Beaufort/Porta/Gronsfeld/Trifid/Vigenere-dict/Hill3) boost only the most-English candidate with continuous score 0.55+0.35·ec; Hill3 scans all block phases and full-crib windows, yields crib match first. | scoring.py, core.py, solvers_pack5/6/7.py | 6 sentences x 6 ciphers = 36/36 correct plaintext #1; run_tests.sh 32/32 PASS |

## Session 3 — Backlog 3 (D1–D2)

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| D1 | `english_confidence(text)`; core caps weak-English non-flag candidates; classical solvers boost only most-English candidate (continuous score); Hill3 scans all phases/windows. | scoring.py, core.py, packs5/6/7 | 36/36 D1 cases correct #1; run_tests.sh 32/32 |
| D2 | test_matrix.py adapted (JSON-parse only) and run (F + E). Fixed to rank #1: plain, hex, base64, base64x2, caesar7, atbash, rot13, rot47, xor1, binary, reverse, E railfence3, E xor1, E xorN. Core: as-is floor .96, 0.97 clamp for non-exact flags, forward-consistency validator, tie-break (ec, subst, plaus delta), atbash authoritative requires plaus gain, xor-short solver (letter-frequency) added. | core.py, solvers_pack7.py, test_matrix.py | F: 11/14; E: 3/7 rank-1; remaining failures documented (tie degeneracy + whitespace/case reconstruction for English). |

## Session 4 — Backlog 3 (D3, D3-fix, D6)

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| D3-fix | Removed debug prints corrupting `--json`; `clear_english()` (dict-gated, printable-ASCII) drives `_english_ok`; consistency bump restricted to trusted bounded key spaces; transposition strong-recovery required ec gain; monoalphabetic substitution multi-seed + boost like other classical solvers. | core.py, scoring.py, solvers.py | 4 regression cases rank #1; matrix all rank 1 except xorN/rail-fence; run_tests 32/32 |
| D3 | `solve_xor_repeating` joint flag-aware search: L<=3 full enumeration (shape-survivor ∪ score-capped), greedy+crib+restart seeds, `_flagaware` objective (flat shape bonus + leet-body dictionary fraction + alnum purity); prior allows low-IC printable ciphertext, excludes text-like/encoded blobs; `WORDS` enriched with CTF/leet vocabulary. | solvers.py, scoring.py | F xorN(k3y) rank #1; 19/20 random 3-byte-key flags rank #1; run_tests 32/32 |
| D6 | Rail-fence flag #1 (matrix failure): strong_recovery now requires start@0 + >=90% span + leet-body dictionary gain (not ec, which never changes under transposition); `solve_rail` keeps up to 8 candidates ordered by dict evidence; braille table extended to full printable ASCII. | core.py, solvers.py, solvers_pack3.py | F railfence3 + E railfence3 rank #1; 10/11 random rail tests (2..6 rails) rank #1; run_tests 32/32; fuzz ALL OK; matrix ALL rank 1 |
| D4 | `test_optional.py`: AES-ECB (pycryptodome) and Fernet (cryptography) rows with PASS/FAIL/SKIP; run_tests.sh runs it as an optional phase after the 32-case table (SKIP when lib missing; non-SKIP FAIL fails the suite). | test_optional.py, run_tests.sh | Both rows SKIP (libs absent), suite exit 0; run_tests still 32/32; matrix unchanged (all rank 1) |
| D5 | Pollard rho batch gcd (512 iters per gcd, was 128); pure-Python Lenstra ECM stage-1 `_ecm` as final fallback in factor_all (affine arithmetic, failed-inverse factor discovery, guards 96–300-bit n), sympy ECM hook preserved. | solvers_more.py | ECM arithmetic matches _ec_mul on 127-bit prime field; planted 40-bit factor recovered ~11s (B1=200k); run_tests 32/32 + optional SKIP rows; fuzz ALL OK; matrix ALL rank 1 |

## Session 5 — Backlog 4 (E1)

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| E1 | Fixtures moved into repo-owned `fixtures/`; `make_fixtures.py` regenerates them deterministically (fixed seed 20261101); `run_tests.sh` uses `$PWD/fixtures` and auto-generates when missing; `test_optional.py` writes into fixtures/. | make_fixtures.py, run_tests.sh, test_optional.py, fixtures/ | fresh generation → 30 files; run_tests 32/32 (+ optional SKIP rows) |
| E2 | `test_blind.py` blind set (seed 20261231, 25 cases). Found real bugs: statistical flag-shaped margin rows outranking evidence; weak leet-body evidence vs fixed-sub ties; short vigenere gated out; small RSA unfactored; L=4 xor missing; bytes-literal not expanding; decoder rows losing ties to key guesses. Fixes in core/solvers/scoring as documented in PROGRESS. | test_blind.py, core.py, solvers.py, solvers_pack7.py | blind 24/25 (96%) ≥90% threshold; run_tests 32/32 |
| E2b | `test_blind2.py` (same generator, blind seed 20270215) run once, no code changes. | test_blind2.py | 21/25 (84%) <90%; failures: atbash, vigenere, hex4, rail5 — investigation pending |
| E2b-fix1 | atbash failure fixed: recovered-attack rows with <90% printable output are demoted (recovered_bad) and lose trust 3; removed a debug-print NameError that silently aborted recovered records. Family: 10 fresh atbash flags (seed 20270301) → 10/10. | core.py, solvers_more.py | run_tests 32/32; family 10/10 |
| E2b-fix2 | vigenere failure fixed: vigenere-dictionary now weaves decrypted letters back into the original text (case/non-letters preserved) and yields up to 12 candidates; previously letters-only uppercase output could never match and true key fell outside top-5. Family: 10 fresh vigenere flags (seed 20270302) → 10/10. | solvers_pack7.py | run_tests 32/32; family 10/10 |
| E2b-fix3 | rail5 failure fixed: clear_english threshold raised (dict fraction ≥0.45) so single-word flukes cannot set _english_ok and outrank recoveries; Franklin-Reiter hardened (N ≥128 bits, c1/c2 < N) with 0 false positives on text containing c1/c2/n. Family: 10 fresh rail flags (seed 20270303) → 10/10. | scoring.py, solvers_pack7.py | run_tests 32/32; family 10/10 |
| E2b-fix4 | hex4 + tie regressions fixed: accidental known-prefix junk (e.g. pwn{) triggered early exit discarding real recoveries — now known-prefix/recovered flags require full-buffer shape; recovered rows keep trust 3 only for flag/English/short technical verdicts, demoted junk capped at 0.55; XOR enumeration skips printable-text blobs; per-node jobs capped at 40. hex4 & vigenere(lemon) #1; run_tests 32/32; matrix all 22 OK. Flagshape tests 4/4. | core.py, solvers.py | run_tests 32/32; matrix all OK; flagshape 4/4 |
| E2b-fix5 | hex-layer family deep diagnosis: depth-0 test (7/8 expansion-type, 1 cipher fail); free fixpoint pre-pass; vigenere-family 48 yields; caesar all-25 on small mixed text; Enigma exact re-elevation; hex-in-text solver; fresh seed 20270306 2/10 (7d+1b) reported untuned. | core.py, solvers.py | run_tests 32/32; matrix all OK; flagshape 4/4 |
| F0 | smooth-composite DLP solver (checkpoint/backtrack p-1 ladder, PH per prime + generalized CRT, verification); challenge.py hex-without-0x & DLP-hint static parsing; fixtures dlp512/dlp1024/dlp_dec_g2/dlp_neg_safe/real_dlp; run_tests rows incl negative budget check. | solvers.py, challenge.py, make_fixtures.py, run_tests.sh | run_tests 37/37; matrix all 22 OK; fuzz OK; flagshape 4/4. Real pair flag: `academy{b3w4r3_0f_c0mp0s1t3_m0dul1_412552aa}` |
| G1 | multi-core -j/--jobs: node-level ProcessPoolExecutor fan-out, deterministic registry-order merge, test_multijob 36/36 equal, pool skip for tiny inputs, Ctrl+C cleanup. Timing (nproc=22) j1/j4: ec 30.24/30.24, dh 30.29/30.25, enigma 30.51/30.27, dlp1024 15.40/19.65, hash 30.24/30.24, fr 30.82/31.30, mt 30.48/46.68, t 4.12/4.00, pp1 0.57/0.57, ecdsa 30.26/30.25; target ≥2× unmet. | core.py, autocrypt.py, solvers.py, test_multijob.py | run_tests 37/37; matrix all OK; fuzz OK; flagshape 4/4 |
| G2 | huge-N linear recurrence + derived key: AST recognizer, companion-matrix fast exponent, key/hash matcher, fixtures real_seq/synth/neg, early exact path, naive test 20/20. Recovered flag (synthetic fixture): `academy{g2_real_seq}`. | solvers.py, autocrypt.py, make_fixtures.py, test_rec_naive.py, run_tests.sh | run_tests 40/40; matrix all OK; fuzz OK; flagshape 4/4; multijob 38/38 |
| G1b | verified-exact grace-gated early exit (G1B_GRACE=1s), futures cancel, per-solver/first-exact metrics, ASCII precompute skip (mt j4≈j1). Post-change j1/j4 table in PROGRESS; run_tests wall 2m47s. | core.py, autocrypt.py | run_tests 40/40; matrix all OK; fuzz OK; flagshape 4/4; multijob 38/38 |
| H1 | hex-layer family fix: fixpoint branch disambiguation (binary before hex, base32 before base64, hex rejects pure 0/1), keep-and-stop on opaque payloads, control-byte blobs → mixed (unblocks XOR priors), early flag exit requires conf ≥0.95, clear_english rejects non-prose punctuation, engok sort jump restricted to non-flag rows. Diagnosis seed 20270306 2/10 → 10/10; fresh 20270307 d12 10/10 (target met), d34 9/10 report-only. | core.py, scoring.py, test_hexfamily.py, diag.py | run_tests 40/40; matrix 22/22; fuzz OK; flagshape OK; multijob 38/38 |
| I1 | adaptive budgets: work-based XOR enumeration (fixed counts, no mid-product abandon, all key lengths), one-time 2x per-solver slice extension on late yields (global room permitting), fixpoint node priority neutral + deeper chain boost, deterministic post-exact drain (≤8 extra nodes, no new expansions after exact). Flake evidence seed 20270308 d34: pre 2/10 cases differed (atbash_L4 empty under load, xor_L4 junk flip), post 0/10 differ idle vs loaded; ecdsa_reuse j1/j4 top-3 stable (was flaky). Fresh: d34 20270308 7/10 report-only; d12 20270309 10/10. | core.py, solvers.py, flakecheck.py | run_tests 40/40; matrix 22/22; fuzz OK; flagshape OK; multijob 38/38 |
| E2b2 | test_blind3.py (same generator as blind2, seed 20270630) one run, no code changes: 22/25 (88.0%) BELOW 90%. Failures: xor4 (rank None), rsa_factored (rank 4), atbash_rot13 (rank None). No failure has ≥3 encoding layers (hex4, b64_hex_b64 pass) — not the known 4-layer weakness. Wall ≈ 4m46s. Not fixed, awaiting decision. | test_blind3.py | run_tests 40/40 |
| J1a | atbash_rot13 fix: affine solver now ranks all 312 keys by max(English, flag-plausibility), flag-shaped outputs by leet-body dictionary fraction (word-aware), yields top 10; true affine(25,12) #1, junk affine(19,8) demoted by core leet-body tie-break. Family seed 20270701 → 10/10 (incl 3 compound compositions). | solvers.py | run_tests 40/40; matrix 22/22; fuzz OK; flagshape OK; multijob 38/38 |
| J1b | rsa_factored fix: verified recovered flag-shaped printable rows confirmed (.98) and exempt from unconfirmed cap; unlabeled n/e/c parse fallback; RSA solver extended slice (30s, global-capped) for labeled moduli. Family seed 20270702 → 10/10 (decimal/hex/unlabeled; large-n synthetic p-1-smooth). | core.py, solvers.py | run_tests 40/40; matrix 22/22; fuzz OK; flagshape OK; multijob 38/38 |
| J1c | xor4 diagnosis only: true combo absent from 24^4 joint space — col2 true byte rank 29 in per-column merge, cut by cap-24; proposal = union caps (≤128) + full product ≤2M presort + _flagaware top 5000. No code change. | — | — |
| K0 | strict mode (env/--strict): bug-class solver exceptions recorded + printed, exit non-zero in strict; run_tests exports STRICT. Found+fixed one real silent bug: straddling-checkerboard IndexError (row1 len 9 vs digit 9). Sweep: strict suites green (run_tests 40/40, matrix 22/22, fuzz, flagshape, hexfamily fresh 10/10 both, blind3 24/25). | core.py, autocrypt.py, run_tests.sh, solvers_pack6.py | all suites |
| J1c-impl | xor narrowing implemented: union caps (≤128), 40k deterministic trim (shape-only, widest last), presort +4×leet-frac, leet tie-break, L5 gate n≤60, seed-product ascent ≤128 seeds, high restarts only on non-textual nodes. Fresh xorfamily seed 20270703 → 7/10 (target 9/10 NOT met; L=3/5 wide-column misses), flake idle=loaded 0 diffs; blind3 seen-data 23/25; fuzz OK. | solvers.py, test_xorfamily.py | see PROGRESS |
| E2b3 | test_blind4.py (blind seed 20270901, one run, report-only): 25/25 (100%). rsa_small modulus 128→192-bit primes so m³<n holds. | test_blind4.py | — |
| E3a | realistic CTF pairs REBUILT: 15 pairs under fixtures/e3/ (synthetic flags, seed 20270710, builder in e3_section.py), flags absent from all files with generation assertions. Strict test_e3.py one run: c05 PASS genuine; c06 FAIL→fixed; all others FAIL true-absent (c09-c15 added). | e3_section.py, make_fixtures.py, test_e3.py | run_tests 40/40 |
| RSA-p/q fix | RSA-extra prior matches p/q labels and ≥4-int text; solve_rsa derives n=p·q and decrypts via φ(n) when p/q given; unlabeled p q e c fallback. Fresh family seed 20270720: 10/10 rank #1 <2s; c06 now 0.3s. | solvers.py, solvers_more.py, test_rsapqfamily.py | all suites |
| E3 proof+diagnosis | 13/13 independent ref-solves OK (fixtures/e3_ref/, no broken pairs); invocation check (combined vs output-only identical junk); parse diagnosis groups S=8 (hint propagation/Hastad labels/LFSR crib), A=3 (common-modulus/FR/hash attempts), P=2 (c01 envelope, c15 hex-whitespace). | e3_ref/, diag_e3.py | — |
| c05 fix | verified-exact/flag accept printable flag-shaped exact recoveries via _flagout_ok (is_flagish too strict for underscore-heavy bodies). Fresh family seed 20270721: 10/10 <3s; c05 wall 30.5s→0.24s. | core.py, test_rsaexactfamily.py | all suites |
| E3-A/c15 fixes | common-modulus separators (space/: /=, hex) 10/10 <3s; FR a·m+b generalization 10/10 <3s; hash label parsing + hash→XOR pairing 10/10 <3s; sep-hex token recognition (fingerprint/decoder/fixpoint) 2/10 <3s (target unmet; scheduler latency). Negatives 0 FP. Plus fixed K0 os-shadow, mis-placed decorator, base_method ordering, recovered-cap statistical exemption. | solvers.py, solvers_pack7.py, solvers_plus.py, solvers_more.py, core.py, test_families_turn.py | all suites (strict) |

## Session 6 — env bring-up + hint propagation (E3 cycle 2 partial), 2026-11-05

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| ENV | No system Python (Microsoft Store stubs); `uv python install 3.12.16`, project `.venv`, `python3.exe` shim in `.venv/Scripts`; `pillow==13.0.0` installed for `lsb_png`. | .venv/, run_tests.sh | run_tests 40/40 reachable |
| H2 | Hint propagation from challenge.py: `dlp_hint` (inline `pow(g,int,n)` → `a=<int>`; `pow(g,SECRET,n)` secret detection), `byte_hints` (key/secret/password/salt str/bytes Constants → hex); `_hint_lines()` emits additive markers on every return path; DH p/g/A/B/enc restoration. New hint-consumer solvers (`hint-secret-xor`, `hint-caesar`, `hint-vigenere`) fire at prior .99 with marker. | challenge.py, solvers.py, test_hints.py | 7/7 markers; E3 S-group c02/c03/c04/c07/c12/c13/c15 green |
| H3 | (a) fr_unlabeled: console-encoding crash (cp1252 U+FFFD) — `sys.stdout/stderr.reconfigure(errors="replace")` fixes; (b) c10 Hastad: shared-`e` triples in `solve_rsa`, token-strip before hex scanning, `labeled_lines` whitelist + `known_labels` → c10 PASS; (c) lsb_png via Pillow. | solvers.py, challenge.py, autocrypt.py | c10 PASS; run_tests 40/40 |
| Regression | Full suite re-run: matrix --both 22/22 rank #1; multijob 38/38 equal; run_tests 40/40. E3 strict: 7/15 PASS (c02,c05,c06,c07,c10,c13,c15); c12 solves but BUDGET; c01/c03#2/c04/c08/c09/c11/c14 still failing. | — | all green, E3 7/15 |

## Session 7 — real online CTF challenges + multi-prime RSA fix, 2026-11-05

| Step | What changed | Files | Verified |
|------|--------------|-------|----------|
| R1 | Curated 3 real picoCTF crypto challenges from public writeups into `real_challenges/` (isolated dir, downloaded data treated as untrusted): **miniRSA** (single-file N/e=3/c), **Many Prime** (multi-file challenge.py + output.txt, 4 primes), **rotation** (single-file ROT ciphertext). | real_challenges/minirsa/, real_challenges/multiprime/, real_challenges/rotation/ | miniRSA solved instantly (small-e exact root); rotation solved (caesar shift 8); multiprime TIMED OUT (pre-fix) |
| R2 | Root-caused multiprime timeout: source had all 4 primes (p1..p4) but challenge.py hint extraction only whitelisted key/secret/password/salt + a few numeric constants — primes were dropped, so the RSA solver tried to factor a 372-bit composite in its 4s slice. Fixed hint propagation: `_hint_lines` now emits `pN=`/`qN=` constants for multi-prime (p/q + digit suffix, >1000) sources. | challenge.py | load() now emits p1..p4 |
| R3 | `solve_rsa_extra` gained a given-primes short-circuit: if the hint primes' product == n, compute φ=∏(p-1) and decrypt — checked BEFORE factor_all (so a large modulus never costs a slice), and `return` immediately after a verified known-multi-prime recovery (previously it fell through to factor_all and burned the deadline). | solvers_more.py | RSA-extra yields known-multi-prime in 0.00s |
| R4 | Main `solve_rsa` (prior 0.99, runs FIRST) starved the search: it got a 30s extension and factored a 372-bit composite, exhausting the global deadline before RSA-extra (0.85) ran. Ported the same given-primes fast path into `solve_rsa`, and extended `_rsa_values`' label regex to capture `p\d*|q\d*` (and to retain p/q keys through normalization). | solvers.py | CLI multiprime at 20s → instant flag; full run returns `picoCTF{mul71_rsa_0f2cedbf}` |
| R5 | Fix labeled-line extraction for 0x-hex output: the regex `[0-9a-fA-F]+` didn't accept the `0x` prefix, so `n = 0x...` / `c = 0x...` lines were dropped entirely (multi-file hex challenges lost n/c). Now accepts optional `0x`, and value parsing detects explicit 0x (so `e=0x10001` isn't misread as decimal). | challenge.py | hex multi-file merged data now carries n/e/c + primes |
| R6 | New family test `test_rsamultiprimefamily.py` (seed 20271105, 10 cases: single-file decimal/hex + multi-file source/output, decimal/hex): 0/10 → 8/10 → 10/10, each rank #1 and <0.5s. Added real multiprime pair into `fixtures/multiprime_real/` and registered a `run_tests.sh` row (expects `picoCTF{mul71_rsa_0f2cedbf}`). | test_rsamultiprimefamily.py, fixtures/multiprime_real/, run_tests.sh | family 10/10; run_tests 41/41 |
| Regression | Full suite after changes: run_tests 41/41 (incl. new multiprime; even_e one-off timing flake 20.5s → PASS on re-run); matrix/multijob/flagshape/fuzz re-verified. | — | all green |

## Final state
- `bash run_tests.sh` → 40/40 PASS
- `python3 fuzz.py` → ALL FUZZ CASES OK
- `python3 test_matrix.py --both` → all 22 rows rank #1 (no remaining failures)
- Backlog 3 (D1–D6) and Backlog 4 (E1–E2b-fix5) complete; blind set 1: 24/25 (96%); blind set 2: 21/25 (84%) → fixes f1–f5 done; hex-layer family fresh seeds 20270305 2/10 and 20270306 2/10 (7×d + 1×b), reported, not re-tuned; flag-shape regressions 4/4.
- F0 (smooth-composite DLP) complete: solver + hex parsing + fixtures + negative budget check; run_tests 37/37, matrix all 22 OK, fuzz OK, flagshape 4/4. Real pair recovered flag: `academy{b3w4r3_0f_c0mp0s1t3_m0dul1_412552aa}`.
- G1 (multi-core) complete: -j/--jobs, node-level ProcessPoolExecutor fan-out, deterministic merge, test_multijob 36/36 equal, Ctrl+C cleanup, negative safety. Timing table (nproc=22): ec_sample 30.24/30.24, dh_dlp 30.29/30.25, enigma 30.51/30.27, dlp1024 15.40/19.65, hash 30.24/30.24, fr_labeled 30.82/31.30, mt19937 30.48/46.68, t.txt 4.12/4.00, pp1 0.57/0.57, ecdsa 30.26/30.25 (j1/j4). Target ≥2× not met (deadline-dominated workloads); regressions stay green.
- G2 (huge-N linear recurrence + derived key) complete: recognizer, fast matrix recurrence, key/hash matcher, fixtures real_seq/synth/neg, early exact path, naive test 20/20. run_tests 40/40, matrix 22/22, fuzz OK, flagshape 4/4, multijob 38/38. Recovered flag (synthetic fixture, real file absent): `academy{g2_real_seq}`.
- G1b (early exit on verified exact recovery) complete: verified-exact grace-gated early exit, futures cancel, per-solver/first-exact metrics, ASCII precompute skip. Post-change timings in PROGRESS; run_tests wall 2m47s 40/40; matrix 22/22; fuzz OK; flagshape 4/4; multijob 38/38.
- H1 (hex-layer family fix) complete: fixpoint branch disambiguation (binary before hex, base32 before base64, hex rejects pure 0/1), keep-and-stop on opaque payloads, control-byte blobs → mixed (unblocks XOR priors), early flag exit requires conf ≥0.95, clear_english rejects non-prose punctuation, engok sort jump restricted to non-flag rows. Diagnosis seed 20270306 2/10 → 10/10; fresh 20270307 d12 10/10 (target met), d34 9/10 report-only.
- I1 (timing-robust adaptive budgets) complete: work-based XOR enumeration (fixed counts, all key lengths), one-time 2x slice extension on late yields, fixpoint priority neutral + deeper chain boost, deterministic post-exact drain (≤8 extra nodes). Flake evidence seed 20270308 d34: pre 2/10 cases differed idle vs loaded; post 0/10 differ; ecdsa_reuse j1/j4 top-3 stable. Fresh: d34 20270308 7/10 report-only; d12 20270309 10/10. Regressions green.
- E2b2 (blind set 3, seed 20270630, one run, no changes): 22/25 (88.0%) — below 90% target, recorded, not fixed. Failures: xor4, rsa_factored, atbash_rot13; none has ≥3 encoding layers (4-layer hex4 passed) → real bugs, not the known deep-layer weakness.
- J1a (atbash_rot13) fixed: affine ranks all 312 keys by max(English, flag-plausibility), flag-shaped outputs by leet-body dictionary fraction; yields top 10. Family seed 20270701 → 10/10.
- J1b (rsa_factored) fixed: verified flag-shaped printable recovered rows confirmed; unlabeled n/e/c fallback; RSA extended slice for labeled moduli. Family seed 20270702 → 10/10 (large-n synthetic p-1-smooth, labeled).
- J1c (xor4) diagnosed, not fixed: true combo cut by per-column cap-24 (col2 true byte rank 29); proposal recorded in PROGRESS Next 0.
- K0 (strict mode) complete: env/--strict, bug-class exception recording, run_tests strict. One real silent bug surfaced+fixed (straddling-checkerboard IndexError).
- J1c-impl complete (partial): union caps, deterministic 40k trim, leet-aware presort/tie-break, L5 gate, seed-product ascent, restart gating. Fresh family 7/10 (< target 9/10, reported honestly); flake 0 diffs; blind3 seen-data 23/25; fuzz OK; follow-up deferred.
- E2b3 (blind set 4, seed 20270901, one run, report-only): 25/25 (100%).
- E3a (realistic CTF pairs) rebuilt: 15 pairs, flags absent (asserted); strict harness table recorded (c05 PASS, c06 FAIL→fixed, rest true-absent). c06-type RSA p/q fix + fresh family 10/10 <2s.
- E3 solvability proof: 13/13 ref-solves OK; invocation check; P/S/A diagnosis recorded. c05 early-exit fix verified (10/10 <3s fresh).
- E3-A/c15 fixes complete per family (common/FR/hash 10/10; sep-hex 2/10 <3s not met); negatives 0 FP; regressions green strict.
- Known remaining: deep layered top-cipher chains (vigenere/atbash/xor over encodings, depth 3-4) still miss ~3/10 at the 15s budget (loading-stable but not solved) — targeted by E3/E6 next.

## Session 8 — more real CTF challenges: Sum-O-Primes (RSA p+q leak) + New Caesar (b16 cipher)

### R1 — Sum-O-Primes (multi-file .py + output.txt, RSA p+q leak, hex output)
- Downloaded real picoCTF Sum-O-Primes pair (`gen.py` + `output.txt`) into `real_challenges/sumoprimes/`.
- Challenge: `x = p + q` is leaked (in hex); with `n = p*q`, solving `t² − x·t + n = 0` recovers p/q and decrypts. `e=65537`, `c` given.
- Initial result: FAIL. autocrypt mis-decoded the hex `x/n/c` lines as quoted-printable → monoalphabetic garbage (conf 0.60, not English). Root cause: the `RSA-sum-leak` solver (solvers_pack3.py) only matched variable names `p_plus_q`/`sum_pq`/`pq_sum`/`s` — the real challenge names the sum `x`.
- Fix in solvers_pack3.py:
  - matcher regex now also accepts `x` as a sum variable;
  - `_pick(..., "s", "x")` includes `x`.
- After fix: CLI recovers the real flag: `picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_24929c45}` (conf 0.98). This is the first multi-file hex RSA challenge solved end-to-end.

### R2 — New Caesar (custom b16 nibble-encode + shift mod 16; .py + .enc)
- Downloaded real picoCTF New Caesar `new_caesar.py` (encryption logic) and obtained the real ciphertext (`output.enc`) from the public writeup.
- Cipher: each plaintext byte → 2 nibbles, each nibble indexes `ALPHABET = "abcdefghijklmnop"` (first 16 lowercase); then each char is Caesar-shifted by a one-char key (mod 16). Ciphertext is purely `[a-p]`, even length.
- Initial result: FAIL. autocrypt had no solver for this custom cipher — the search mis-decoded it as reverse-each-word → monoalphabetic garbage.
- Added solver `new-caesar-b16` (solvers_pack3.py): takes the longest contiguous `[a-p]` run, brute-forces all 16 possible single-char shifts, decodes nibble pairs to bytes, keeps the highest-scoring printable plaintext. Correct key recovered as `chr(98)` = `b`, yielding the real flag.picoCTF{et_tu?_5723f4e71a0736d3b1d19dde4279ac03}`.

### R3 — hint-line leakage fix in the New-Caesar solver
- Bug: the merged multi-file data included the hint line `key_bytes=0x62`; naive `re.sub(r"[^a-p]", ...)` concatenated the k/e/b letters from the hint into the nibble stream → trailing garbage bytes (`\x93\x03`).
- Fix: solver now picks the *longest contiguous* `[a-p]` run (the actual ciphertext) instead of all a-p letters. Multi-file result now clean and exact.

### Regression
- Full suite re-run after changes (40+ rows) — see PROGRESS.
- New `run_tests.sh` rows: `real_pqsum` (expects real picoCTF Sum-O-Primes flag) and `real_newcaesar` (expects real picoCTF New Caesar flag).
