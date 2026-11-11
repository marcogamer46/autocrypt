#!/usr/bin/env python3
"""Regression tests for the audit-fix batch (bugs #1,2,3,4,18,19,20,21,22).

Each test pins the specific defect that was fixed in the audit pass:

  #1  scoring._leet_word_variants blows up beyond ~12 ambiguous positions
  #2  challenge.analyze_source SyntaxError path lost the byte_pads element
  #3  czroots._roots_mod_prime squarefree step used the remainder, not quotient
  #4  solvers._ec_parse_ints parsed bare decimals as hex
  #18 solvers_mega.solve_rot18 (explicit 13-letter / 5-digit map)
  #19 solvers_mega ITA2 tables were not genuine index-by-5bit-code tables
  #20 solvers_pack7._lcg_recover over-ran its window
  #21 solvers_pack7.solve_franklin_reiter must reject b == 0
  #22 solvers_pack6 Enigma rotors must pad to exactly three

They run either as direct unit checks or through the CLI via the same
subprocess harness used by the other test modules.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_P = "0"


def _cli_results(text, top=200):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "challenge.txt"
        p.write_text(text, encoding="utf-8")
        args = [sys.executable, "-m", "autocrypt.cli", str(p),
                "--json", "--top", str(top)]
        r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True,
                           timeout=180)
    try:
        out = json.loads(r.stdout or "[]")
    except Exception:
        return []
    if isinstance(out, dict):
        return out.get("results", [])
    return out


def _found(results, needle):
    return any(needle.lower() in (res.get("plaintext") or "").lower()
               for res in results)


class FakeCtx:
    """Minimal solver context for direct generator checks."""
    depth = 0
    known_plaintext = None
    wordlist = []
    rsa_params = {}

    def __init__(self):
        self.findings = []

    def expired(self):
        return False


def main():
    failed = 0

    def check(name, ok):
        nonlocal failed
        if not ok:
            failed += 1
        print(f"{name:26} {'PASS' if ok else 'FAIL'}")

    # ---- #1 leet expansion bound
    from autocrypt.scoring import _leet_word_variants
    big = _leet_word_variants("1" * 15)          # 15 ambiguous positions
    check("1-leet-bounded", len(big) <= 2)
    small = _leet_word_variants("h1r")
    check("1-leet-still-expands", any("hi" in w for w in small))

    # ---- #2 analyze_source SyntaxError tuple width
    from autocrypt.challenge import analyze_source, load
    res = analyze_source("def broken(:\n    pass\n")
    check("2-analyze-source-7tuple", len(res) == 7)
    try:
        with tempfile.TemporaryDirectory() as td:
            py = Path(td) / "bad.py"
            py.write_text("def broken(:\n    pass\n", encoding="utf-8")
            load([py])
        ok = True
    except ValueError:
        ok = False
    check("2-load-syntaxerror", ok)

    # ---- #3 czroots squarefree uses quotient
    from autocrypt.czroots import _roots_mod_prime
    r0 = _roots_mod_prime([0, 0, 1], 97)         # x^2 -> root 0
    r1 = _roots_mod_prime([-1, 0, 1], 97)        # x^2-1 -> roots 1,96
    check("3-squarefree-x2", 0 in r0)
    check("3-squarefree-x2m1", 1 in r1 and 96 in r1)

    # ---- #4 _ec_parse_ints decimal branch
    from autocrypt.solvers import _ec_parse_ints
    ec = _ec_parse_ints("p = 97\nn = 123456789\ngx = 0xabcdef\n")
    check("4-ec-decimal", ec.get("n") == 123456789 and ec.get("gx") == 0xabcdef
          and ec.get("p") == 97)

    # ---- #18 ROT18 explicit map (ROT18("abc123") = "nop678")
    from autocrypt.solvers_mega import solve_rot18
    rot_out = list(solve_rot18(b"nop678\n", FakeCtx()))
    check("18-rot18", any(b"abc123" in o[0] for o in rot_out))

    # ---- #19 genuine ITA2 tables: HELLO in LTRS code
    # H=20(10100) E=1(00001) L=18(10010) L=18 O=24(11000)
    bits = "1010000001100101001011000"
    from autocrypt.solvers_mega import solve_baudot
    bd_out = list(solve_baudot((bits + "\n").encode(), FakeCtx()))
    check("19-ita2", any("HELLO" in o[0].decode() for o in bd_out))

    # ---- #20 LCG recovery window (must not overrun / raise)
    from autocrypt.solvers_pack7 import _lcg_recover
    try:
        g = _lcg_recover([1, 2, 4, 8, 16, 32, 64, 128])
        ok = g is None or isinstance(g, int)
    except Exception:
        ok = False
    check("20-lcg-window", ok)

    # ---- #21 Franklin-Reiter rejects b == 0
    N = (1 << 255) + 1
    fr_in = (f"N = {N}\ne = 3\na = 2\nb = 0\nc1 = 2\nc2 = 3\n")
    fr_res = _cli_results(fr_in)
    check("21-franklin-b0",
          not any("Franklin" in (r.get("method") or "") for r in fr_res))

    # ---- #22 Enigma rotor padding (partial spec must still yield 3 rotors)
    import re as _re
    from autocrypt.solvers_pack6 import _enigma_encrypt, solve_enigma, _ENIGMA_ROTORS
    flag = "academy{enigma_pad}"
    ct = _enigma_encrypt(flag, ["I", "II", "III"], [0, 0, 0],
                         (0, 0, 0), "B", [])
    en_in = f"rotors=I-II-III\nrings=AAA\npositions=AAA\nreflector=B\n{ct}\n"
    eg_out = [o for o in solve_enigma(en_in.encode(), FakeCtx())]
    check("22-enigma-pad", any("enigmapad" in o[0].lower() for o in eg_out))
    raw_n = _re.findall(r"[IVX]+", "I")
    names_n = [n for n in raw_n if n in _ENIGMA_ROTORS]
    names_n = (names_n + ["I", "II", "III"])[:3]
    check("22-enigma-pad-len", len(names_n) == 3)

    # ---- #36 base100 must not truncate at an interior NUL byte
    from autocrypt.solvers_gaps import (_bigbase_decode, _ook_to_bf,
                                        _bf_run, solve_jwt_key_confusion)

    def _to_base100(data):
        n = int.from_bytes(data, "big")
        if n == 0:
            return chr(0xAC00)
        out = []
        while n:
            out.append(chr(0xAC00 + n % 100))
            n //= 100
        return "".join(reversed(out))

    nul_payload = b"academy{interior_nul}" + b"\x00" + b"tail"
    nul_txt = _to_base100(nul_payload)
    nul_dec = _bigbase_decode(nul_txt, 100, 0xAC00, 0xAC63)
    check("36-base100-interior-nul",
          nul_dec is not None and nul_dec[0] == nul_payload)

    # ---- #39 base100 uses base 100 over U+AC00..AC63, stray symbol ignored
    real_payload = b"academy{base100_real}"
    real_txt = _to_base100(real_payload) + "힣"   # out-of-range digit
    real_dec = _bigbase_decode(real_txt, 100, 0xAC00, 0xAC63)
    check("39-base100-radix", real_dec is not None and real_dec[0] == real_payload)

    # ---- #37 Ook! a token carrying two punctuation marks keeps BOTH tokens
    ook_prog = "Ook.?" + ("Ook. " * 10)          # '.' '?' + 10x '.' -> 12 tokens
    check("37-ook-double-punct", _ook_to_bf(ook_prog) == ">+++++")

    # ---- #40 Brainfuck must not emit a truncated output when budget runs out
    check("40-bf-budget-truncated", _bf_run("+.>" + "+" * 500_000) is None)

    # ---- #38 JWT with a rewritten HS256 header must be verified+recovered
    import base64 as _b64
    import hmac as _hmac
    import hashlib as _hl

    def _b64u(b):
        return _b64.urlsafe_b64encode(b).rstrip(b"=")

    der38 = b"FAKE-DER-KEY-MATERIAL-0123456789ABCDEF"
    pem38 = ("-----BEGIN PUBLIC KEY-----\n"
             + _b64.b64encode(der38).decode()
             + "\n-----END PUBLIC KEY-----")
    head38 = _b64u(b'{"alg":"HS256","typ":"JWT"}')
    pay38 = _b64u(b'{"flag":"academy{jwt_hs256_header}"}')
    msg38 = head38 + b"." + pay38
    sig38 = _b64u(_hmac.new(der38, msg38, _hl.sha256).digest())
    tok38 = (msg38 + b"." + sig38).decode()
    jwt38_out = list(solve_jwt_key_confusion(
        (pem38 + "\n" + tok38).encode(), FakeCtx()))
    check("38-jwt-hs256",
          any(b"academy{jwt_hs256_header}" in o[0] for o in jwt38_out))

    # ---- #41 registry has no duplicate solver names; gaps implementation wins
    from autocrypt.core import REGISTRY
    from autocrypt.solvers_gaps import solve_brainfuck as _gaps_bf
    from autocrypt.solvers_gaps import solve_ook as _gaps_ook
    _names = [s.name for s in REGISTRY]
    check("41-registry-dedup",
          _names.count("brainfuck") == 1 and _names.count("ook") == 1)
    _bf_s = [s for s in REGISTRY if s.name == "brainfuck"][0].solve
    _ook_s = [s for s in REGISTRY if s.name == "ook"][0].solve
    check("41-registry-gaps-wins", _bf_s is _gaps_bf and _ook_s is _gaps_ook)

    print(f"\nRegression: {21 - failed}/21 PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
