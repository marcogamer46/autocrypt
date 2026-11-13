"""Phase 7 tests: RSA UI mode — optional private exponent (d), p/q path,
multi-line/single-line paste, hex autodetection, block-RSA, and validation.

Covers:
  - solve_data with a `params`/spec containing d decrypts directly.
  - d-only decryption (n, c, d) works WITHOUT a public exponent e.
  - p/q-given path derives d from phi(n) and decrypts.
  - The ascii label scan reads n/e/c/p/q/d from a pasted blob.
  - Uppercase / 0X / bare-hex values auto-detect correctly.
  - Multi-line labeled paste and a full single-line spec both parse and solve.
  - Missing required fields are handled without a crash.
  - A wrong d never crashes and never emits a confident garbage RSA result.
  - Block RSA (many ciphertext values sharing n/e) is recovered.
  - The recovered plaintext bytes exactly equal pow(c, d, n).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"

from autocrypt.cli import _params, solve_data  # noqa: E402
from autocrypt.ui import _parse_rsa_spec, _rsa_value_to_decimal  # noqa: E402

# Fixed 160-bit RSA example (p, q prime; e=65537; d = e^-1 mod phi).
_N = 1529126172105859265296750435999243616292734566641993528351400573286353450778757371251991073199901
_E = 65537
_D = 5343087010577868559027051129038967119810736160648917032256124552140856679176367969171590563841
_C = 1104974295606153792856111660558223963524164748301831197722079801379508532840183434301534090891720
_P = 1347461523292874612230125392714613414960817243649
_Q = 1134819915576542457287848603590235585508287473949
_FLAG = "academy{rsa_known_d_ok}"

# Real per-character block-RSA challenge (n=1260503 = 1019*1237, e=65537).
_BLOCK_CT = "251027 566556 4941 1033225 1118860 251027 209017 898188 898188 1033225 251027 763848 646453 1009530 356135 813296 410920 410920 497547 356135 957330 1123062 993354 410920 993354 1009530 497547 1009530 356135 813296 410920 410920 497547 911485 204585 957330 362860 410920 1166696 356135 1259179"
_BLOCK_FLAG = "cyberconnect{small_modulus_small_problem}"
_BLOCK_N = 1260503
_BLOCK_E = 65537


def _solve(data, **kw):
    _, res, _ = solve_data(data, timeout=12, top=30, jobs=1, **kw)
    return res


def _has_flag(res, flag):
    flag = flag.lower()
    return any(flag in r.get("plaintext", "").lower() for r in res)


def test_solve_data_param_with_d():
    spec = f"n={_N},e={_E},c={_C},d={_D}"
    res = _solve(spec.encode())
    assert _has_flag(res, _FLAG), [r.get("plaintext", "")[:40] for r in res]


def test_solve_data_ascii_scan_d():
    blob = f"n={_N}\ne={_E}\nc={_C}\nd={_D}\n".encode()
    res = _solve(blob)
    assert _has_flag(res, _FLAG), [r.get("plaintext", "")[:40] for r in res]


def test_d_only_without_e():
    # n, c, d (no e) must decrypt via m = c^d mod n.
    spec = f"n={_N},c={_C},d={_D}"
    res = _solve(spec.encode())
    assert _has_flag(res, _FLAG), [r.get("chain") for r in res[:3]]
    assert any("RSA known-d" in r.get("chain", "") for r in res)


def test_pq_path_derives_d():
    # p/q given (no d) -> d derived from phi(n); e required.
    spec = f"n={_N},e={_E},c={_C},p={_P},q={_Q}"
    res = _solve(spec.encode())
    assert _has_flag(res, _FLAG), [r.get("chain") for r in res[:3]]
    assert any("RSA" in r.get("chain", "") for r in res)


def test_params_spec_parses_d():
    p = _params(f"n={_N},e={_E},c={_C},d={_D},p={_P},q={_Q}")
    assert p["n"] == _N and p["e"] == _E and p["c"] == _C
    assert p["d"] == _D and p["p"] == _P and p["q"] == _Q


def test_hex_autodetect():
    # 0X uppercase, bare-hex letters, and decimals all parse to the same int.
    for val, expect in [("0x" + hex(_N)[2:], _N),
                        ("0X" + hex(_E)[2:].upper(), _E),
                        (hex(_C)[2:], _C),  # bare hex (contains a-f)
                        (hex(_D)[2:], _D),
                        (str(_P), _P),      # plain decimal
                        (str(_Q), _Q)]:
        dv = _rsa_value_to_decimal(val)
        assert dv and int(dv) == expect, (val, dv)


def test_parse_rsa_spec_multiline_uppercase():
    text = f"N=0X{hex(_N)[2:].upper()}\ne : {_E}\nc = {_C}\nPRIV=0x{hex(_D)[2:]}\n"
    fields, unknown = _parse_rsa_spec(text)
    assert not unknown, unknown
    assert int(fields["n"]) == _N
    assert int(fields["e"]) == _E
    assert int(fields["c"]) == _C
    assert int(fields["d"]) == _D


def test_multiline_full_paste_solves():
    blob = f"n={_N}\ne={_E}\nc={_C}\nd={_D}\n".encode()
    res = _solve(blob)
    assert _has_flag(res, _FLAG), [r.get("chain") for r in res[:3]]


def test_singleline_full_spec_solves():
    spec = f"n={_N},e={_E},c={_C},p={_P},q={_Q},d={_D}"
    res = _solve(spec.encode())
    assert _has_flag(res, _FLAG), [r.get("chain") for r in res[:3]]


def test_missing_required_no_crash():
    for spec in (f"n={_N},e={_E}",            # missing c
                 f"e={_E},c={_C}",           # missing n
                 f"n={_N},c={_C}"):          # missing e and d
        try:
            _solve(spec.encode())
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"crash on {spec!r}: {exc}")


def test_wrong_d_no_crash_no_garbage():
    # On a modulus too large to factor in-window, a wrong d must neither crash
    # nor emit a confident "RSA known-d" candidate (verification rejects it).
    spec = f"n={_N},e={_E},c={_C},d=12345"
    res = _solve(spec.encode())
    assert not any("RSA known-d" in r.get("chain", "") for r in res), res
    # the crack/factoring paths are still attempted (no crash, results list ok)


def test_block_rsa_challenge():
    data = f"{_BLOCK_CT}\n\nn = {_BLOCK_N}\ne = {_BLOCK_E}\n"
    res = _solve(data.encode())
    assert _has_flag(res, _BLOCK_FLAG), [r.get("chain") for r in res[:3]]
    assert any("RSA block" in r.get("chain", "") for r in res)


def test_plaintext_matches_pow():
    m = pow(_C, _D, _N)
    expect = m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    res = _solve(f"n={_N},e={_E},c={_C},d={_D}".encode())
    assert any(r.get("plaintext") == expect for r in res), res


def test_cli_params_with_d():
    spec = f"n={_N},e={_E},c={_C},d={_D}\n"
    p = subprocess.run(
        [sys.executable, "-m", "autocrypt", "--json"],
        input=spec.encode(), capture_output=True)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    payload = json.loads(p.stdout.decode("utf-8"))
    texts = " ".join(r.get("plaintext", "") for r in payload["results"]).lower()
    assert _FLAG in texts, [r.get("plaintext", "") for r in payload["results"]]


def main():
    test_solve_data_param_with_d()
    test_solve_data_ascii_scan_d()
    test_d_only_without_e()
    test_pq_path_derives_d()
    test_params_spec_parses_d()
    test_hex_autodetect()
    test_parse_rsa_spec_multiline_uppercase()
    test_multiline_full_paste_solves()
    test_singleline_full_spec_solves()
    test_missing_required_no_crash()
    test_wrong_d_no_crash_no_garbage()
    test_block_rsa_challenge()
    test_plaintext_matches_pow()
    test_cli_params_with_d()
    print("RSA-UI-PHASE7: ALL OK")


if __name__ == "__main__":
    main()
