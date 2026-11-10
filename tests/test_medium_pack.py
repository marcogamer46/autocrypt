#!/usr/bin/env python3
"""Regression for the medium-tier solver pack (autocrypt/solvers_pack7.py).

Covers DES / 3DES / Blowfish / ChaCha20 known-key decryption.  All fixtures
are generated with pycryptodome and the expected plaintext is a flag, so the
solver output is flag-shaped and must surface through the CLI.

Beyond the happy path, we verify the robustness fixes from the adversarial
review of the pack:

  * uppercase labels (KEY=/IV=/MODE=) parse AND are stripped from the blob
  * non-ECB modes (CBC / CTR) actually exercise the IV/CTR branches
  * a non-hex ASCII key falls back to literal bytes instead of hex-decoding
  * a challenge explicitly labeled cipher=aes is NOT "solved" by the block
    ciphers (label guard)
  * a prose file with a stray key= label emits no block-cipher candidate
    (stricter evidence gating)
"""
import sys
import subprocess
import tempfile
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _cli_results(p):
    args = [sys.executable, "-m", "autocrypt.cli", str(p), "--json", "--top", "200"]
    r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
    try:
        out = json.loads(r.stdout or "[]")
    except Exception:
        return []
    if isinstance(out, dict):
        out = out.get("results", [])
    return out


def _flag_recovered(results, flag):
    fl = flag.decode() if isinstance(flag, bytes) else flag
    return any(fl.lower() in (res.get("plaintext") or "").lower() for res in results)


def _chain_has(results, substr):
    return any(substr in (res.get("chain") or "") for res in results)


def _check(name, text, flag, expect_recovered=True, bad_chains=()):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = _flag_recovered(results, flag) == expect_recovered
    for bc in bad_chains:
        if _chain_has(results, bc):
            ok = False
    note = "flag recovered" if _flag_recovered(results, flag) else "flag NOT recovered"
    chains = [r.get("chain") for r in results][:4]
    print(f"{name:24} {'PASS' if ok else 'FAIL'} ({note}; chains={chains})")
    return ok


def _pad8(data):
    return data + b" " * (8 - len(data) % 8)


def main():
    failed = False

    # ---- DES / ECB, lowercase labels (baseline)
    try:
        from Crypto.Cipher import DES
        key = b"8bytes!!"
        flag = b"academy{des_key_works}"
        ct = DES.new(key, DES.MODE_ECB).encrypt(_pad8(flag))
        text = f"key={key.hex()}\nmode=ecb\n{ct.hex()}\n"
        failed |= not _check("des-ecb", text, flag)
    except Exception as e:
        failed |= True
        print("des-ecb (exception)", e)

    # ---- DES / ECB, UPPERCASE labels (case-insensitive blob stripping)
    try:
        from Crypto.Cipher import DES
        key = b"8bytes!!"
        flag = b"academy{des_upper_labels}"
        ct = DES.new(key, DES.MODE_ECB).encrypt(_pad8(flag))
        text = f"KEY={key.hex()}\nMODE=ECB\n{ct.hex()}\n"
        failed |= not _check("des-ecb-upper", text, flag)
    except Exception as e:
        failed |= True
        print("des-ecb-upper (exception)", e)

    # ---- DES / CBC with IV
    try:
        from Crypto.Cipher import DES
        key = b"8bytes!!"
        iv = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        flag = b"academy{des_cbc_iv}"
        ct = DES.new(key, DES.MODE_CBC, iv).encrypt(_pad8(flag))
        text = f"key={key.hex()}\niv={iv.hex()}\nmode=cbc\n{ct.hex()}\n"
        failed |= not _check("des-cbc", text, flag)
    except Exception as e:
        failed |= True
        print("des-cbc (exception)", e)

    # ---- DES / CTR with counter IV
    try:
        from Crypto.Cipher import DES
        from Crypto.Util import Counter
        key = b"8bytes!!"
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x01"
        flag = b"academy{des_ctr_counter}"
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, "big"))
        ct = DES.new(key, DES.MODE_CTR, counter=ctr).encrypt(flag)
        text = f"key={key.hex()}\niv={iv.hex()}\nmode=ctr\n{ct.hex()}\n"
        failed |= not _check("des-ctr", text, flag)
    except Exception as e:
        failed |= True
        print("des-ctr (exception)", e)

    # ---- DES / ECB with a NON-HEX ASCII key (fallback to literal bytes)
    try:
        from Crypto.Cipher import DES
        key = b"8bytes!!"          # not valid hex -> must be treated as ASCII
        flag = b"academy{des_ascii_key}"
        ct = DES.new(key, DES.MODE_ECB).encrypt(_pad8(flag))
        text = f"key={key.decode()}\nmode=ecb\n{ct.hex()}\n"
        failed |= not _check("des-ascii-key", text, flag)
    except Exception as e:
        failed |= True
        print("des-ascii-key (exception)", e)

    # ---- 3DES (key 16 bytes, ECB)
    try:
        from Crypto.Cipher import DES3
        key = bytes(range(16))
        flag = b"academy{3des_key_works}"
        ct = DES3.new(key, DES3.MODE_ECB).encrypt(_pad8(flag))
        text = f"key={key.hex()}\nmode=ecb\n{ct.hex()}\n"
        failed |= not _check("3des-ecb", text, flag)
    except Exception as e:
        failed |= True
        print("3des-ecb (exception)", e)

    # ---- Blowfish (key 16 bytes, ECB)
    try:
        from Crypto.Cipher import Blowfish
        key = b"blowfish-key-16"
        flag = b"academy{blowfish_key_works}"
        ct = Blowfish.new(key, Blowfish.MODE_ECB).encrypt(_pad8(flag))
        text = f"key={key.hex()}\nmode=ecb\n{ct.hex()}\n"
        failed |= not _check("blowfish-ecb", text, flag)
    except Exception as e:
        failed |= True
        print("blowfish-ecb (exception)", e)

    # ---- ChaCha20 (key 32 bytes, nonce)
    try:
        from Crypto.Cipher import ChaCha20
        key = bytes(range(32))
        nonce = b"\x00" * 8
        flag = b"academy{chacha20_key_works}"
        ct = ChaCha20.new(key=key, nonce=nonce).encrypt(flag)
        text = f"key={key.hex()}\nnonce={nonce.hex()}\n{ct.hex()}\n"
        failed |= not _check("chacha20", text, flag)
    except Exception as e:
        failed |= True
        print("chacha20 (exception)", e)

    # ---- Label mismatch: a DES-ECB blob explicitly labeled cipher=aes must
    # NOT be claimed by the block-cipher solvers (they run for the real AES
    # solver instead).  The flag should NOT appear from a DES/3DES/Blowfish
    # chain.
    try:
        from Crypto.Cipher import DES
        key = b"8bytes!!"
        flag = b"academy{des_but_labeled_aes}"
        ct = DES.new(key, DES.MODE_ECB).encrypt(_pad8(flag))
        text = f"cipher=aes\nkey={key.hex()}\nmode=ecb\n{ct.hex()}\n"
        failed |= not _check("label-mismatch-aes", text, flag,
                             expect_recovered=False,
                             bad_chains=("DES", "3DES", "Blowfish", "ChaCha20"))
    except Exception as e:
        failed |= True
        print("label-mismatch-aes (exception)", e)

    # ---- No-crypto prose: a sentence with a stray key= label and no hex
    # ciphertext must emit no block-cipher candidate (evidence gating).
    prose = ("key=deadbeef\nMeet me at the old bridge near the river at "
             "midnight with the documents.\n")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "prose.txt"
        p.write_text(prose, encoding="utf-8")
        results = _cli_results(p)
    ok = not _chain_has(results, "DES") and not _chain_has(results, "3DES") \
        and not _chain_has(results, "Blowfish") \
        and not _chain_has(results, "ChaCha20")
    note = "block-cipher chains=" + json.dumps(
        [r.get("chain") for r in results if r.get("chain") and any(
            s in r["chain"] for s in ("DES", "3DES", "Blowfish", "ChaCha20"))])
    print(f"{'no-crypto-prose':24} {'PASS' if ok else 'FAIL'} ({note})")
    failed |= not ok

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
