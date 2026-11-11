#!/usr/bin/env python3
"""Regression for the gap-filling solvers introduced in 0.10.3:

  * ``powershell-encodedcommand`` - base64 of UTF-16LE (PowerShell
    -EncodedCommand) is decoded back to readable text containing the flag.
  * ``unicode-tag-stego`` - Unicode tag characters (U+E0000..E007F) map to
    ASCII and recover the flag.
  * ``java-random`` - recovers a java.util.Random seed from consecutive
    nextInt() outputs; the seed matches and >3 outputs confirm.
  * ``jwt-key-confusion`` - an RS256-header JWT whose signature is an HMAC
    keyed with the RSA public key resolves to the payload flag.

Each fixture feeds the CLI and asserts the flag (or the recovery marker) shows
up in the JSON results.
"""
import sys
import json
import base64
import hmac
import hashlib
import random
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_RND_A = 0x5DEECE66D
_RND_B = 0xB
_RND_MASK = (1 << 48) - 1


def _cli_results(p):
    args = [sys.executable, "-m", "autocrypt.cli", str(p), "--json", "--top", "200"]
    r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
    try:
        out = json.loads(r.stdout or "[]")
    except Exception:
        return []
    if isinstance(out, dict):
        return out.get("results", [])
    return out


def _flag_recovered(results, flag):
    fl = flag.decode() if isinstance(flag, bytes) else flag
    return any(fl.lower() in (res.get("plaintext") or "").lower() for res in results)


def _case(name, text, flag):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = _flag_recovered(results, flag)
    print(f"{name:24} {'PASS' if ok else 'FAIL'} (methods="
          f"{[r.get('method') for r in results][:4]})")
    return ok


def _case_marker(name, text, marker, expect=True):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        results = _cli_results(p)
    ok = any(marker in (r.get("plaintext") or "") for r in results)
    passed = ok if expect else not ok
    print(f"{name:24} {'PASS' if passed else 'FAIL'} ({'found' if ok else 'absent'} "
          f"marker; methods={[r.get('method') for r in results][:4]})")
    return passed


def _to_bigbase(data, base, lo):
    n = int.from_bytes(data, "big")
    if n == 0:
        return chr(lo)
    out = []
    while n:
        out.append(chr(lo + n % base))
        n //= base
    return "".join(reversed(out))


def _rnd_ints(seed, n):
    s = (seed ^ _RND_A) & _RND_MASK
    out = []
    for _ in range(n):
        s = (s * _RND_A + _RND_B) & _RND_MASK
        v = s >> 16
        out.append(v - (1 << 32) if v >= (1 << 31) else v)
    return out


_BF_TO_OOK = {">": ".?", "<": "?.", "+": "..", "-": "!!",
               ".": "!.", ",": ".!", "[": "!?", "]": "?!"}


def _bf_to_ook(code):
    # Each Brainfuck instruction is a pair of Ook! tokens ("Ook." "Ook?" ...).
    toks = []
    for c in code:
        p1, p2 = _BF_TO_OOK[c]
        toks.append("Ook" + p1)
        toks.append("Ook" + p2)
    return " ".join(toks)


def _bf_print(s):
    """A Brainfuck program that prints ``s`` (per-char increment) output)."""
    return "".join("+" * ord(ch) + ".>" for ch in s)


def _mt_stream(seed, n):
    rng = random.Random(seed)
    return [rng.getrandbits(32) for _ in range(n)]


def _jwt(secret, flag):
    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")
    head = b64u(b'{"alg":"RS256","typ":"JWT"}')
    pay = b64u(json.dumps({"flag": flag}).encode())
    msg = head + b"." + pay
    sig = b64u(hmac.new(secret, msg, hashlib.sha256).digest())
    return (msg + b"." + sig).decode()


def main():
    failed = False

    # ---- PowerShell -EncodedCommand: base64 of UTF-16LE
    flag1 = b"academy{gap_ps_encoded}"
    ps = base64.b64encode(flag1.decode().encode("utf-16-le")).decode()
    failed |= not _case("powershell-encoded", f"{ps}\n", flag1)

    # ---- Unicode tag stego
    flag2 = "academy{gap_unicode_tag}"
    tagified = "".join(chr(ord(c) + 0xE0000) for c in flag2)
    prose = "Some normal chat text here " + tagified + " and more context."
    failed |= not _case("unicode-tag", prose, flag2)

    # ---- java.util.Random seed recovery
    seed = 0xDEAD_BEEF
    ints = _rnd_ints(seed, 5)
    jtext = "Random outputs: " + ", ".join(str(i) for i in ints) + "."
    failed |= not _case_marker("java-random", jtext, f"seed {seed}")

    # ---- JWT RS256->HS256 key confusion (wrapped multi-line PEM)
    der = b"FAKE-DER-KEY-MATERIAL-0123456789ABCDEF" * 4
    b64pem = base64.b64encode(der).decode()
    wrapped = "\n".join(b64pem[i:i + 64] for i in range(0, len(b64pem), 64))
    pem = "-----BEGIN PUBLIC KEY-----\n" + wrapped + "\n-----END PUBLIC KEY-----"
    flag4 = "academy{gap_jwt_confusion}"
    tok = _jwt(der, flag4)
    failed |= not _case("jwt-key-confusion", pem + "\n" + tok + "\n", flag4)

    # ---- Java-random negative control: unrelated integers must NOT fire
    decoy = "The scores were 42, 7, 1337, 9001, 12345."
    failed |= not _case_marker("java-random-negative", decoy, "seed=", expect=False)

    # ---- base100 (Hangul): base-11172 big integer as Hangul syllables
    flag5 = b"academy{gap_base100}"
    hangul = _to_bigbase(flag5, 11172, 0xAC00)
    failed |= not _case("base100", "payload: " + hangul + "\n", flag5)

    # ---- MD5 / SHA-1 hash-length-extension primitives (edge-case sweep)
    from autocrypt.solvers_gaps import _md5_extend, _sha1_extend, _md5_pad, _sha1_pad
    md5_bad = sha1_bad = 0
    for ap in (0, 1, 7, 55, 56, 57, 63, 64, 65, 127, 128, 129):
        for ml in (0, 5, 55, 56, 64, 129):
            secret = bytes(range(16))
            msg = b"x" * ml
            append = b"y" * ap
            L = len(secret) + len(msg)
            m0 = hashlib.md5(secret + msg).digest()
            forged = msg + _md5_pad(L) + append
            if _md5_extend(m0, L, append) != hashlib.md5(secret + forged).digest():
                md5_bad += 1
            s0 = hashlib.sha1(secret + msg).digest()
            forged1 = msg + _sha1_pad(L) + append
            if _sha1_extend(s0, L, append) != hashlib.sha1(secret + forged1).digest():
                sha1_bad += 1
    md5_ok = md5_bad == 0
    sha1_ok = sha1_bad == 0
    print(f"{'md5-length-extension':24} {'PASS' if md5_ok else 'FAIL'} (bad={md5_bad})")
    print(f"{'sha1-length-extension':24} {'PASS' if sha1_ok else 'FAIL'} (bad={sha1_bad})")
    failed |= not md5_ok
    failed |= not sha1_ok

    # ---- Brainfuck interpreter
    flag6 = "academy{bf_esolang}"
    bf_code = _bf_print(flag6)
    failed |= not _case("brainfuck", bf_code, flag6)

    # ---- Ook! interpreter (spaced token form)
    ook_prog = _bf_to_ook(bf_code)
    failed |= not _case("ook", ook_prog, flag6)

    # ---- MT19937 (Python random) clone: 633 outputs -> next-8 prediction
    mt_vals = _mt_stream(20241111, 633)
    mt_text = "Random stream: " + ", ".join(str(v) for v in mt_vals)
    failed |= not _case_marker("mt19937-clone", mt_text, "MT19937")

    # ---- MT19937 negative control: sequential pseudo-ints must NOT fire
    seq = ", ".join(str(i) for i in range(700))
    failed |= not _case_marker("mt19937-negative", seq, "MT19937", expect=False)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
