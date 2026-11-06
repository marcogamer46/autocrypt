# Session.md — durable continuation ledger

> Purpose: when a Claude Code session stops unexpectedly (crash, close, `/clear`), this file is the single source of truth so the next session can resume without rediscovering state. Update it at the **end of every working turn** (status, what's next, commands). Also see `PROGRESS.md` / `LOGS.md` (fuller history) and `things_it_cant_solve.txt`.

## How to resume
- Same machine, Claude Code: `claude --continue` (most recent session) or `claude --resume <session-id>` (any saved session — sessions ARE saved to disk and resumable, so check `claude --resume` list before starting fresh).
- This file is the fallback if resume is unavailable (e.g. different machine / lost context).

## Last known state (2026-11-05, updated by automation)
- Repo: `C:\Users\juanm\Documents\project\autocrypt`, branch `main`.
- Live work: **challenge `real_challenges/e5_270rsa_rev/`** — 270-bit RSA, hard-factoring.
  - `n = 1368992139315019955067447961537607041364451719382349005056752379702694554965203011` (270 bits)
  - `e = 65537`, `c = 717608817902276639011922897702552744324264244069272484013719744328086856277690292`
  - `output.txt` holds `n / e / c`; nothing else. Decrypting needs factoring `n`.
  - Assumed balanced ~135-bit primes (generic semiprime).
- Untracked scratch scripts tried so far: `_final_check.py`, `_ecmA.py`, `_ecmB.py` (trial div → 1e6, Fermat, Pollard p-1 @ B=1e6, ECM B1≈100–200k).
  - Result: no small factor, no perfect power, gcd(c,n)=1, p-1 B=1e6 failed, ECM B1≈150–200k failed.
  - → consistent with balanced 135-bit semiprime.
- Environment: Windows 11, git bash, `.venv` = pure Python. **No** sympy / gmpy2 / primefac / numpy / cryptography installed.

## Current technical verdict
- Pure-Python factoring of a 270-bit balanced semiprime is **not tractable** for the general case: needs QS/GNFS (C/GMP-backed: yafu, msieve, gmp-ecm). This is the documented hard limit (see README + things_it_cant_solve.txt).
- Only remaining pure-Python methods with any realistic chance:
  1. Pollard p-1 with high B (B=1e7–1e8) **if** a factor's p−1 is smooth — cheap-ish, worth one run.
  2. Pollard p+1 (Brent). Same caveat.
  3. ECM at high B1 (B1≥1e6, thousands of curves) for a ~40-digit factor — orders of magnitude too slow in pure Python (days+).

## Factoring attempt results (2026-11-05)
- Trial division → 1e6: no factor. Fermat: none. Perfect power: none. gcd(c,n)=1.
- Pollard p-1 @ B=1e6: failed (_final_check).
- ECM B1≈100–200k, 8–12 curves: failed (_ecmA/_ecmB).
- Pollard p-1 @ B=1e7: **failed** (~10s, `_pm1_1e7.txt`).
- Brent p+1 @ B=1e7: **failed** (~18s, `_p1_1e7.txt`).
- Pollard p-1 @ B=1e8: **failed** (~97s, `_pm1_1e8.txt`).
- Consistent with balanced ~135-bit semiprime.

## Conclusion (decisive)
All pure-Python factoring methods that have any realistic chance have now been exhausted:
trial div → 1e6, Fermat, p-1 @ 1e6/1e7/1e8, p+1 @ 1e7, ECM @ B1≈100–200k.
None found a factor. **This modulus is a balanced ~135-bit semiprime; general factoring requires QS/GNFS (C/GMP-backed), which is not tractable in pure Python.**
User decision (2026-11-05): **Install tools & retry**. ✅

## Tool install status (2026-11-05)
- `ensurepip` bootstrapped pip into `.venv` (was absent).
- Installed `gmpy2 2.3.2` + `primefac 2.0.12` via `.venv/Scripts/python.exe -m pip`.
- **In progress:** `_solve_e5.py` → primefac.factorint(n) then decrypt (d = e^{-1} mod φ, m = c^d mod n). Background task bnam0f6i7, output `_e5_solved.txt`.

## e5 SOLVED (2026-11-06) — verified ✅
- `primefac.primefac(n)` → factors p=2074606527507983503944226222695401999839 (131b) and q=659880377875535146491994798968813949893149 (139b), p*q==n.
- Decryption: d = e^{-1} mod φ, m = c^d mod n → raw bytes are the plaintext *reversed* (`_rev` challenge). Reversed: `academy{sma11_N_n0_g0od_a3ac7152}`.
- This was solved by peer session after handoff; verified independently here.
- Note: the e5 file was written by the peer session; verify `_e5_solved.txt` is canonical, or consolidate into a clean record.

## SOLVED (2026-11-05, Session 14)
- e5_270rsa_rev is **SOLVED**. Factorization via factordb (external QS/GNFS):
  - p = 2074606527507983503944226222695401999839 (131 bits)
  - q = 659880377875535146491994798968813949893149 (139 bits)
  - d = e^-1 mod φ, m = c^d mod n
  - Decrypted bytes are REVERSED (challenge "_rev"): raw was
    `}\n2517ca3a_do0g_0n_N_11ams{ymedaca` → reversed →
    **FLAG = `academy{sma11_N_n0_g0od_a3ac7152}`**
- Solution recorded in `_e5_solved.txt`; tracker/LOGS/PROGRESS updated.

## Next steps
- (Done) e5 solved; update PROGRESS.md, things_it_cant_solve.txt, README.
- Optional future: add a transparent QS/GNFS/factordb hook to the RSA solver for
  >192-bit semiprimes (currently external-only).


## Recurring workflow notes
- `run_tests.sh` is the full regression suite (was 43/43). Run before/after solver changes.
  - NOTE: on this Windows box `python3` is NOT on PATH nand the Store alias shadows it). The test suites call `python3` both in-shell AND via subprocess (which ignores shell-only shims). Correct invocation:
    `PATH="$PWD/.venv/Scripts:$PATH" bash run_tests.sh` (and same PATH for `test_e3/e4/matrix/flagshape/...`).
  - `.venv/Scripts/python3.exe` exists; prepending that dir to PATH fixes both shell and subprocess.
  - Verified post-change: run_tests 43/43, test_e4 10/10, test_e3 15/15, test_flagshape OK.
  - `test_matrix --both`: 21/22 OK. One *pre-existing flaky* row: `xorN (hex, key=k3y)` — intermittently `FAIL top='-'` (2/3 pass); in isolation the solver recovers it 4/4 at rank #0 (key `k3y`, ±0.97). Not caused by current changes (solver untouched); environmental slice-expiry flake. Known-ambiguous XOR family limitation (README: target ~7/10). Left as-is to avoid destabilizing the solver.
- Commit discipline: commit with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Keep scratch experiment scripts out of tracked history unless promoted to solvers.

## Session 14 (2026-11-06) — online-training drive (raw challenges only, no leaked flags)
- Source: `Adamkadaban/CTFs` (GitHub, branch `master`) — bundles original challenge files. Downloaded into `real_challenges/online_train/` via `_download_train.py` (per-challenge subdirs; never executed, `-I`-style isolation).
- **Code changes (training-driven):**
  1. `challenge.py`: added `_concat_label` + `_LABEL_HINTS`; `_label` now recognizes `print("e:"+str(e))`-style BinOp conCAT (was mislabeled generic `x1/x2`). Affects all real CTF .py files.
  2. `solvers.py`: added "RSA small-e exact root (no modulus)" branch in `solve_rsa` for when only `e`+`c` are labeled (no `n` printed).
- **Results on raw challenges:**
  - `Baby_RSA` (CSAW Red 2020): ✅ `flag{really_s1ck_algor1thm}` (already solved pre-fix via p/q fallback).
  - `Teen_RSA` (CSAW Red 2020, e=3, no n): ✅ `flag{where_did_my_primes_go?}` — the fix (label + no-modulus root) unlocked it; verified correct.
  - `rotation` (picoCTF 2023): ✅ `picoCTF{r0tat1on_d3crypt3d_70c23f2f}` via caesar(8).
  - `Caesar_Salad_Edition` (CSAW Red 2020): ❌ autocrypt short-circuits as-is (input is flag-shape `y4tz{...}`). Real answer is a Caesar/shift of "flag{...}" + leet; NOT solved. Gap: as-is early-return blocks body decode.
  - `XtraORdinary` (redpwn): ⚠️ partial — found `hex → repeating-key XOR` but wrong key; needs crib-assisted key recovery (key not among the 4 known strings directly). Gap.
  - `Double_DES` (picoCTF 2021): out of scope (DES, no support).
  - `NSA_Backdoor` (picoCTF 2022): ✅ served `picoCTF{cf58a7b8}` via "Cracked DLP (smooth composite)" path (flag body plausible; treat as provisional — DLP solver path, not RSA p−1). Verify against official later.
  - `Very_Smooth` (picoCTF 2022): ❌ failed (garbage). Needs Pollard p−1 with B≈2^16; autocrypt's p−1 didn't fire / B too small. Gap → TODO: raise p−1 B or add smooth-prime heuristic when source shows `get_smooth_prime`.
  - `New_Vignere` (picoCTF 2021): no separate output.txt (embedded `correctOut` in source); TODO.
- Regression: full `run_tests.sh` running (43 cases) — awaiting result to confirm the two code changes are non-breaking.
