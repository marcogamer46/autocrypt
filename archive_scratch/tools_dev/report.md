# autocrypt — project report

Status snapshot (generated after Backlog 3 + Backlog 4 + F0/G1/G2/G1b).

---

## 1. What this is

`autocrypt` is a CLI fingerprint/search pipeline for CTF-style crypto challenges:
it takes an unknown blob (or a challenge `.py` + `output.txt` pair), runs a
bounded best-first decode search, and ranks candidate plaintexts (flags, English
text, exact attack verdicts). Every solver is stateless per node, honors
`ctx.expired()`, never executes challenge code, and flag detection is
content-agnostic.

## 2. Current verification state

| Suite | Result |
|---|---|
| `bash run_tests.sh` | **40/40 PASS** (wall ≈ 2m47s) |
| `python3 test_matrix.py --both` | **22/22 rank #1** |
| `python3 fuzz.py` | ALL FUZZ CASES OK |
| `python3 test_flagshape.py` | 4/4 OK |
| `python3 test_multijob.py` | 38/38 identical top-3 at -j1 vs -j4 |
| `python3 test_rec_naive.py` | 20/20 OK (matrix vs naive recurrence) |
| `python3 test_optional.py` | AES/Fernet SKIP (libs absent), suite exit 0 |

Known deliberate limitations (documented, not regressions):

- **Deep layered top-cipher chains** (vigenere/atbash/xor over encodings):
  fresh blind hex-layer seeds still mostly fail at the cipher-solve stage —
  category (d) dominates; reported, not re-tuned (7×d+1×b on 20270306).
- **Blind sets**: seed 20261231 → 24/25 (96%); seed 20270215 → 21/25 (84%,
  failures fixed individually: atbash, vigenere, rail5, hex4). Third-seed
  estimate (20270630) not yet run (blocked by adaptive-budget step).
- **Timing**: dlp1024 ≈ 15–16s, hash ≈ 30s remain above the 5s exact-exit
  target (Pollard p-1 ladder cap / brute-force hash search).
- **G2 "real" pair** is a synthetic fixture rebuilt from the spec (the real
  `real_seq` file was absent from the repo).

## 3. Backlog completion map

### Backlog 1 — B1..B14 (solvers & ranking foundations)
Flag-aware ranking, permuting-method gates, permutation-xor plurality:
RSA p±1/rho/ECM factoring, EC/ECDSA/DSA, knapsack, straddling checkerboard,
Z85/custom base, Enigma M3, LSB/WAV stego, etc.

### Backlog 2 — C1..C20
Decoder-unknown-prefix ranking, literal/CRT/radix parsers, DSA/RSA leaks,
Franklin-Reiter, LCG/MT19937, DH-DLP, RC4/AES glue, hash cracking, classical
cipher solvers, extra encodings, stego, JSON/verbose CLI, 32-case regression
table, fuzz, per-solver 4s shares, README.

### Backlog 3 — D1..D6
- D1: `english_confidence` + classical most-English boosts (36/36).
- D2: matrix re-creation, ranking/consistency rules, xor-short.
- D3-fix: `clear_english`, trusted key-space consistency bump, substitution
  multi-seed boost; 4 regression cases restored.
- D3: short multi-byte XOR joint search (L≤4 enumeration, flag-aware
  objective); F xorN(k3y) rank #1; 19/20 D3 random.
- D4: AES/Fernet tests with SKIP rows.
- D5: rho batch gcd + pure-Python ECM fallback.
- D6: rail-fence #1 (start@0 + span ≥90% + leet-body dict gain); braille
  table extended; matrix fully rank 1.

### Backlog 4 — E1..E8
- E1: repo-owned `fixtures/` + deterministic `make_fixtures.py`.
- E2/E2b: blind sets (25 cases) — found and fixed real bugs (statistical
  margin junk, evidence tiers, short-vigenere gating, RSA factoring fallback,
  L=4 XOR, bytes-literal expansion, decoder-vs-guess ties, oracle-prefix
  early-exit, single-word `clear_english` flukes, hex4 early-exit discard).
- E3–E8: pending (realistic CTF set, challenge labeling, --explain,
  performance pass, --no-brute/--deep, README).

### F0 — smooth-composite DLP
`dlp-composite-smooth`: checkpoint/backtrack Pollard p-1 ladder
(B 2^12..2^18), Pohlig-Hellman per prime over smooth r−1, generalized CRT
(non-coprime orders), verification `g^x ≡ c (mod n)`. Hex-without-0x parsing
and `pow(g, SECRET, n)` static hint detection in `challenge.py`. Real-pair
recovery: `academy{b3w4r3_0f_c0mp0s1t3_m0dul1_412552aa}`.

### G1 — multi-core execution
`--jobs/-j` (default min(cpu_count,8); 1 = exact sequential). Node-level
fan-out via one `ProcessPoolExecutor` per run, deterministic registry-order
merge, no nested pools (`AUTOCRYPT_WORKER`), pool skipped for tiny inputs,
Ctrl+C cleanup. `test_multijob.py` 38/38 top-3 identical. Speed target ≥2×
not met — workloads are deadline-dominated; ASCII-text precompute is skipped
to avoid contention (mt19937 j4 ≈ j1).

### G1b — early exit on verified exact recovery
Verified exact rows (known-prefix/full-buffer flags, confirmed attacks, exact
decodes, non-flag verified verdicts) stop expanding after a configurable grace
(`G1B_GRACE`, default 1.0s), cancel pool futures, rank and exit. Junk
accidental prefixes remain blocked by the full-buffer shape rule. Added
per-solver/first-exact metrics under `--verbose`. Most previously-30s cases
now finish in 1–3s. Remaining >5s: dlp1024 (ladder cap), hash (brute).

### G2 — huge-N linear recurrence + derived key
Static AST recognizer extracts recurrence order/coeffs/base cases, N, modulus,
verification hash and `bytes.fromhex` ciphertext. Fast companion-matrix
exponentiation (2.4s for N=2e7, M=10^10000; verified vs naive 20/20). Key
derivation matcher tries md5/sha1/sha256/sha512/blake2b forms, verifies hash
constants, derives cycled XOR key, accepts flag-shaped/English output. Early
exact path in `solve_data` before the full search. Recovered flag (synthetic
fixture): `academy{g2_real_seq}`.

## 4. Architecture notes

- `core.py`: best-first search, node expansion gates, trust tiers, evidence
  gates, free fixpoint pre-pass, verified-exact early exit, per-solver time
  accounting, job cap (top 40 by prior).
- `solvers*.py`: registry-driven solver modules (classical, RSA/EC/DLP,
  encodings, XOR, hash, stego, recurrence).
- `scoring.py`: quadgram/English/leet-body-dict evidence models.
- `challenge.py`: static AST analysis of `.py` (labels, hex formats, DLP
  hints); never executes challenge code.
- `make_fixtures.py`: deterministic generation of all `fixtures/` files
  (fixed seeds); `run_tests.sh` auto-regenerates when missing.

## 5. How to run

```bash
bash run_tests.sh                 # 40/40 regression table
python3 test_matrix.py --both     # 22/22 rank-1
python3 fuzz.py                   # malformed-input smoke
python3 test_flagshape.py         # flag-shape regressions
python3 test_multijob.py          # -j1 vs -j4 determinism
python3 autocrypt.py message.txt
python3 autocrypt.py fixtures/real_dlp/output.txt fixtures/real_dlp/gen.py
python3 autocrypt.py --jobs 1 fixtures/real_seq/sequences.py
```

## 6. Roadmap / next steps

1. Adaptive time budgets (extend a still-progressing solver once, up to 2×,
   if the global deadline has room)
2. `test_blind3.py` (seed 20270630), one run — target ≥90%
3. Hex-layer family deep diagnosis under the new budgets (category d focus)
4. E3 realistic CTF set, E4 challenge labeling, E5 `--explain`, E6
   performance pass, E7 `--no-brute`/`--deep`, E8 README overhaul
